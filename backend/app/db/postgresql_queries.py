import psycopg2
import psycopg2.extras
import os
from datetime import datetime
import logging
from typing import Optional, Dict, Any, List
import json

# Importer les fonctions de base de données unifiées
from .database import get_db_connection, release_db_connection, execute_query, get_db_cursor

def update_meeting(meeting_id: str, user_id: str, update_data: Dict[str, Any]) -> bool:
    """Mettre à jour un meeting dans PostgreSQL - Version unifiée"""
    try:
        # Construire la requête de mise à jour
        set_clauses = []
        values = []
        
        for key, value in update_data.items():
            if key in ['metadata'] and isinstance(value, dict):
                # Convertir les dictionnaires en JSON pour PostgreSQL
                set_clauses.append(f"{key} = %s")
                values.append(json.dumps(value))
            else:
                set_clauses.append(f"{key} = %s")
                values.append(value)
        
        if not set_clauses:
            return False
        
        values.extend([datetime.utcnow(), meeting_id, user_id])
        
        query = f"""
            UPDATE meetings 
            SET {', '.join(set_clauses)}, updated_at = %s
            WHERE id = %s AND user_id = %s
        """
        
        rowcount = execute_query(query, tuple(values))
        return rowcount > 0
        
    except Exception as e:
        logging.error(f"Erreur lors de la mise à jour du meeting {meeting_id}: {e}")
        raise

def get_meeting(meeting_id: str, user_id: str = None) -> Optional[Dict[str, Any]]:
    """Récupérer un meeting par ID - Version unifiée"""
    try:
        if user_id:
            query = "SELECT * FROM meetings WHERE id = %s AND user_id = %s"
            params = (meeting_id, user_id)
        else:
            query = "SELECT * FROM meetings WHERE id = %s"
            params = (meeting_id,)
        
        meeting = execute_query(query, params, fetch='one')
        
        if meeting:
            # Convertir les champs JSON si nécessaire
            if meeting.get('metadata') and isinstance(meeting['metadata'], str):
                try:
                    meeting['metadata'] = json.loads(meeting['metadata'])
                except:
                    pass
            
            # Normaliser les champs pour compatibilité
            meeting['id'] = str(meeting['id'])
            meeting['user_id'] = str(meeting['user_id'])
            
            return meeting
        
        return None
        
    except Exception as e:
        logging.error(f"Erreur lors de la récupération du meeting {meeting_id}: {e}")
        raise

def normalize_transcript_format(text: str) -> str:
    """Normaliser le format du texte de transcription"""
    if not text:
        return ""
        
    # Si le texte contient déjà des marqueurs de locuteurs au format 'Speaker X: ', on le laisse tel quel
    if "Speaker " in text and ": " in text:
        return text
        
    # Sinon, on le considère comme un texte brut d'un seul locuteur
    return f"Speaker A: {text}"

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
