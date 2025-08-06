import psycopg2
import psycopg2.extras
import os
from datetime import datetime
import logging
from typing import Optional, Dict, Any, List
import json

# Configuration PostgreSQL
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://gilbert_user:gilbertmdp2025@postgres:5432/gilbert_db")

def get_db_connection():
    """Obtenir une connexion PostgreSQL"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        logging.error(f"Erreur de connexion PostgreSQL: {e}")
        raise

def update_meeting(meeting_id: str, update_data: Dict[str, Any]) -> bool:
    """Mettre à jour un meeting dans PostgreSQL"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Construire la requête de mise à jour
        set_clauses = []
        values = []
        
        for key, value in update_data.items():
            if key in ['transcript_json', 'metadata'] and isinstance(value, dict):
                # Convertir les dictionnaires en JSON
                set_clauses.append(f"{key} = %s")
                values.append(json.dumps(value))
            else:
                set_clauses.append(f"{key} = %s")
                values.append(value)
        
        values.append(meeting_id)
        
        query = f"""
            UPDATE meetings 
            SET {', '.join(set_clauses)}, updated_at = %s
            WHERE id = %s
        """
        values.append(datetime.utcnow())
        
        cursor.execute(query, values)
        conn.commit()
        
        return cursor.rowcount > 0
        
    except Exception as e:
        if conn:
            conn.rollback()
        logging.error(f"Erreur lors de la mise à jour du meeting: {e}")
        raise
    finally:
        if conn:
            conn.close()

def get_meeting(meeting_id: str) -> Optional[Dict[str, Any]]:
    """Récupérer un meeting par ID"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cursor.execute(
            "SELECT * FROM meetings WHERE id = %s",
            (meeting_id,)
        )
        
        meeting = cursor.fetchone()
        
        if meeting:
            # Convertir les champs JSON
            if meeting.get('transcript_json'):
                meeting['transcript_json'] = json.loads(meeting['transcript_json'])
            if meeting.get('metadata'):
                meeting['metadata'] = json.loads(meeting['metadata'])
            
            return dict(meeting)
        
        return None
        
    except Exception as e:
        logging.error(f"Erreur lors de la récupération du meeting: {e}")
        raise
    finally:
        if conn:
            conn.close()

def normalize_transcript_format(transcript_data: Dict[str, Any]) -> Dict[str, Any]:
    """Normaliser le format de transcription"""
    if not transcript_data:
        return {}
    
    # Si c'est déjà un dictionnaire, le retourner
    if isinstance(transcript_data, dict):
        return transcript_data
    
    # Si c'est une chaîne JSON, la parser
    if isinstance(transcript_data, str):
        try:
            return json.loads(transcript_data)
        except:
            return {}
    
    return {}

def get_meeting_speakers(meeting_id: str) -> List[Dict[str, Any]]:
    """Récupérer les speakers d'un meeting"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cursor.execute(
            "SELECT * FROM speakers WHERE meeting_id = %s ORDER BY created_at",
            (meeting_id,)
        )
        
        speakers = cursor.fetchall()
        return [dict(speaker) for speaker in speakers]
        
    except Exception as e:
        logging.error(f"Erreur lors de la récupération des speakers: {e}")
        return []
    finally:
        if conn:
            conn.close()

def create_speaker(speaker_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Créer un nouveau speaker"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cursor.execute(
            """
            INSERT INTO speakers (meeting_id, name, confidence, start_time, end_time, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (
                speaker_data["meeting_id"],
                speaker_data["name"],
                speaker_data.get("confidence", 0.0),
                speaker_data.get("start_time", 0.0),
                speaker_data.get("end_time", 0.0),
                datetime.utcnow()
            )
        )
        
        speaker = cursor.fetchone()
        conn.commit()
        
        return dict(speaker) if speaker else None
        
    except Exception as e:
        if conn:
            conn.rollback()
        logging.error(f"Erreur lors de la création du speaker: {e}")
        raise
    finally:
        if conn:
            conn.close()

def update_speaker(speaker_id: str, update_data: Dict[str, Any]) -> bool:
    """Mettre à jour un speaker"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        set_clauses = []
        values = []
        
        for key, value in update_data.items():
            set_clauses.append(f"{key} = %s")
            values.append(value)
        
        values.append(speaker_id)
        
        query = f"""
            UPDATE speakers 
            SET {', '.join(set_clauses)}, updated_at = %s
            WHERE id = %s
        """
        values.append(datetime.utcnow())
        
        cursor.execute(query, values)
        conn.commit()
        
        return cursor.rowcount > 0
        
    except Exception as e:
        if conn:
            conn.rollback()
        logging.error(f"Erreur lors de la mise à jour du speaker: {e}")
        raise
    finally:
        if conn:
            conn.close()

def create_meeting(meeting_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Créer un nouveau meeting"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cursor.execute(
            """
            INSERT INTO meetings (user_id, title, audio_file_path, status, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (
                meeting_data["user_id"],
                meeting_data.get("title", ""),
                meeting_data.get("audio_file_path", ""),
                meeting_data.get("status", "pending"),
                datetime.utcnow(),
                datetime.utcnow()
            )
        )
        
        meeting = cursor.fetchone()
        conn.commit()
        
        return dict(meeting) if meeting else None
        
    except Exception as e:
        if conn:
            conn.rollback()
        logging.error(f"Erreur lors de la création du meeting: {e}")
        raise
    finally:
        if conn:
            conn.close()

def get_meetings_by_user(user_id: str) -> List[Dict[str, Any]]:
    """Récupérer tous les meetings d'un utilisateur"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cursor.execute(
            "SELECT * FROM meetings WHERE user_id = %s ORDER BY created_at DESC",
            (user_id,)
        )
        
        meetings = cursor.fetchall()
        return [dict(meeting) for meeting in meetings]
        
    except Exception as e:
        logging.error(f"Erreur lors de la récupération des meetings: {e}")
        return []
    finally:
        if conn:
            conn.close()

def delete_meeting(meeting_id: str) -> bool:
    """Supprimer un meeting"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM meetings WHERE id = %s", (meeting_id,))
        conn.commit()
        
        return cursor.rowcount > 0
        
    except Exception as e:
        if conn:
            conn.rollback()
        logging.error(f"Erreur lors de la suppression du meeting: {e}")
        raise
    finally:
        if conn:
            conn.close() 
