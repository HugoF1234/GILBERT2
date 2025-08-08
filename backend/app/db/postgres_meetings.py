import asyncio
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from .postgres_database import get_db_connection


def _run(coro):
    """Run an async coroutine in a short-lived event loop, returning its result.
    Keeps a sync API for existing call sites.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def normalize_transcript_format(text: Optional[str]) -> Optional[str]:
    if not text:
        return text
    import re
    pattern = r'(^|\n)(?!Speaker )([A-Z0-9]+): '
    replacement = r'\1Speaker \2: '
    return re.sub(pattern, replacement, text)


async def _create_meeting_async(meeting_data: Dict[str, Any], user_id: str) -> Optional[Dict[str, Any]]:
    async with get_db_connection() as conn:
        meeting_id = str(uuid.uuid4())
        created_at = datetime.utcnow()
        await conn.execute(
            """
            INSERT INTO meetings (
              id, user_id, title, file_url, transcript_status, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6)
            """,
            uuid.UUID(meeting_id), uuid.UUID(user_id), meeting_data.get("title"),
            meeting_data.get("file_url"), meeting_data.get("transcript_status", "pending"), created_at
        )
        row = await conn.fetchrow("SELECT * FROM meetings WHERE id = $1", uuid.UUID(meeting_id))
        if row:
            result = dict(row)
            result["id"] = str(result["id"]) if result.get("id") else None
            result["user_id"] = str(result["user_id"]) if result.get("user_id") else None
            if result.get("created_at"):
                result["created_at"] = result["created_at"].isoformat()
            return result
        return None


def create_meeting(meeting_data: Dict[str, Any], user_id: str) -> Optional[Dict[str, Any]]:
    return _run(_create_meeting_async(meeting_data, user_id))


async def _get_meeting_async(meeting_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    async with get_db_connection() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM meetings WHERE id = $1 AND user_id = $2",
            uuid.UUID(meeting_id), uuid.UUID(user_id)
        )
        if not row:
            return None
        d = dict(row)
        d["id"] = str(d["id"]) if d.get("id") else None
        d["user_id"] = str(d["user_id"]) if d.get("user_id") else None
        if d.get("created_at"):
            d["created_at"] = d["created_at"].isoformat()
        if d.get("transcript_text"):
            d["transcript_text"] = normalize_transcript_format(d["transcript_text"])
        # compat
        d["transcription_status"] = d.get("transcript_status", "pending")
        return d


def get_meeting(meeting_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    return _run(_get_meeting_async(meeting_id, user_id))


async def _get_meetings_by_user_async(user_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
    async with get_db_connection() as conn:
        if status:
            rows = await conn.fetch(
                """
                SELECT * FROM meetings
                WHERE user_id = $1 AND transcript_status = $2
                ORDER BY created_at DESC
                """,
                uuid.UUID(user_id), status,
            )
        else:
            rows = await conn.fetch(
                "SELECT * FROM meetings WHERE user_id = $1 ORDER BY created_at DESC",
                uuid.UUID(user_id),
            )
        result: List[Dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            d["id"] = str(d["id"]) if d.get("id") else None
            d["user_id"] = str(d["user_id"]) if d.get("user_id") else None
            if d.get("created_at"):
                d["created_at"] = d["created_at"].isoformat()
            if d.get("transcript_text"):
                d["transcript_text"] = normalize_transcript_format(d["transcript_text"])
            d["transcription_status"] = d.get("transcript_status", "pending")
            result.append(d)
        return result


def get_meetings_by_user(user_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
    return _run(_get_meetings_by_user_async(user_id, status))


async def _update_meeting_async(meeting_id: str, user_id: str, update_data: Dict[str, Any]) -> bool:
    if not update_data:
        return False
    # normalize transcript text if present
    if update_data.get("transcript_text"):
        update_data["transcript_text"] = normalize_transcript_format(update_data["transcript_text"])  

    async with get_db_connection() as conn:
        set_parts = []
        values = []
        idx = 1
        for k, v in update_data.items():
            set_parts.append(f"{k} = ${idx}")
            values.append(v)
            idx += 1
        # where params
        values.append(uuid.UUID(meeting_id))
        values.append(uuid.UUID(user_id))
        query = f"UPDATE meetings SET {', '.join(set_parts)} WHERE id = ${idx} AND user_id = ${idx+1}"
        res = await conn.execute(query, *values)
        return res and res.upper().startswith("UPDATE")


def update_meeting(meeting_id: str, user_id: str, update_data: Dict[str, Any]) -> bool:
    return _run(_update_meeting_async(meeting_id, user_id, update_data))


async def _delete_meeting_async(meeting_id: str, user_id: str) -> Optional[str]:
    async with get_db_connection() as conn:
        row = await conn.fetchrow(
            "SELECT file_url FROM meetings WHERE id = $1 AND user_id = $2",
            uuid.UUID(meeting_id), uuid.UUID(user_id)
        )
        if not row:
            return None
        await conn.execute(
            "DELETE FROM meetings WHERE id = $1 AND user_id = $2",
            uuid.UUID(meeting_id), uuid.UUID(user_id)
        )
        return row["file_url"]


def delete_meeting(meeting_id: str, user_id: str) -> Optional[str]:
    return _run(_delete_meeting_async(meeting_id, user_id))


async def _get_meeting_speakers_async(meeting_id: str, user_id: str) -> Optional[List[Dict[str, Any]]]:
    async with get_db_connection() as conn:
        # verify meeting ownership
        m = await conn.fetchrow(
            "SELECT id FROM meetings WHERE id = $1 AND user_id = $2",
            uuid.UUID(meeting_id), uuid.UUID(user_id),
        )
        if not m:
            return None
        rows = await conn.fetch(
            "SELECT * FROM meeting_speakers WHERE meeting_id = $1 ORDER BY speaker_id",
            uuid.UUID(meeting_id),
        )
        return [dict(r) for r in rows] if rows else []


def get_meeting_speakers(meeting_id: str, user_id: str) -> Optional[List[Dict[str, Any]]]:
    return _run(_get_meeting_speakers_async(meeting_id, user_id))


async def _get_pending_transcriptions_async(max_age_hours: int = 24) -> List[Dict[str, Any]]:
    threshold = datetime.utcnow() - timedelta(hours=max_age_hours)
    async with get_db_connection() as conn:
        rows = await conn.fetch(
            "SELECT * FROM meetings WHERE transcript_status = 'pending' AND created_at > $1",
            threshold,
        )
        return [dict(r) for r in rows]


def get_pending_transcriptions(max_age_hours: int = 24) -> List[Dict[str, Any]]:
    return _run(_get_pending_transcriptions_async(max_age_hours))


async def _get_meetings_by_status_async(status: str, max_age_hours: int = 72) -> List[Dict[str, Any]]:
    threshold = datetime.utcnow() - timedelta(hours=max_age_hours)
    async with get_db_connection() as conn:
        rows = await conn.fetch(
            """
            SELECT * FROM meetings
            WHERE transcript_status = $1 AND created_at > $2
            ORDER BY created_at DESC
            """,
            status, threshold,
        )
        return [dict(r) for r in rows]


def get_meetings_by_status(status: str, max_age_hours: int = 72) -> List[Dict[str, Any]]:
    return _run(_get_meetings_by_status_async(status, max_age_hours))


async def _set_meeting_speaker_async(meeting_id: str, user_id: str, speaker_id: str, custom_name: str) -> bool:
    async with get_db_connection() as conn:
        # ensure meeting ownership
        m = await conn.fetchrow(
            "SELECT id FROM meetings WHERE id = $1 AND user_id = $2",
            uuid.UUID(meeting_id), uuid.UUID(user_id)
        )
        if not m:
            return False
        existing = await conn.fetchrow(
            "SELECT id FROM meeting_speakers WHERE meeting_id = $1 AND speaker_id = $2",
            uuid.UUID(meeting_id), speaker_id
        )
        if existing:
            await conn.execute(
                "UPDATE meeting_speakers SET custom_name = $1 WHERE id = $2",
                custom_name, existing["id"],
            )
            return True
        entry_id = str(uuid.uuid4())
        await conn.execute(
            "INSERT INTO meeting_speakers (id, meeting_id, speaker_id, custom_name) VALUES ($1, $2, $3, $4)",
            uuid.UUID(entry_id), uuid.UUID(meeting_id), speaker_id, custom_name,
        )
        return True


def set_meeting_speaker(meeting_id: str, user_id: str, speaker_id: str, custom_name: str) -> bool:
    return _run(_set_meeting_speaker_async(meeting_id, user_id, speaker_id, custom_name))


async def _delete_meeting_speaker_async(meeting_id: str, user_id: str, speaker_id: str) -> bool:
    async with get_db_connection() as conn:
        # verify meeting ownership
        m = await conn.fetchrow(
            "SELECT id FROM meetings WHERE id = $1 AND user_id = $2",
            uuid.UUID(meeting_id), uuid.UUID(user_id)
        )
        if not m:
            return False
        await conn.execute(
            "DELETE FROM meeting_speakers WHERE meeting_id = $1 AND speaker_id = $2",
            uuid.UUID(meeting_id), speaker_id,
        )
        return True


def delete_meeting_speaker(meeting_id: str, user_id: str, speaker_id: str) -> bool:
    return _run(_delete_meeting_speaker_async(meeting_id, user_id, speaker_id))


async def _validate_meeting_ids_async(meeting_ids: List[str], user_id: str) -> List[str]:
    async with get_db_connection() as conn:
        rows = await conn.fetch(
            "SELECT id FROM meetings WHERE id = ANY($1::uuid[]) AND user_id = $2",
            [uuid.UUID(mid) for mid in meeting_ids], uuid.UUID(user_id),
        )
        return [str(r["id"]) for r in rows]


def validate_meeting_ids(meeting_ids: List[str], user_id: str) -> List[str]:
    return _run(_validate_meeting_ids_async(meeting_ids, user_id))


