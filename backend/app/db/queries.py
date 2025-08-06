"""
Module unifié pour toutes les requêtes de base de données Gilbert
Remplace postgresql_queries.py et assure la compatibilité avec l'ancien code SQLite
"""

import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List

from .database import execute_query, get_db_cursor

logger = logging.getLogger(__name__)

# =============================================================================
# FONCTIONS DE GESTION DES RÉUNIONS
# =============================================================================

def create_meeting(meeting_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Créer une nouvelle réunion"""
    try:
        query = """
            INSERT INTO meetings (user_id, title, file_url, transcript_status, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING *
        """
        params = (
            meeting_data["user_id"],
            meeting_data.get("title", ""),
            meeting_data.get("file_url", ""),
            meeting_data.get("transcript_status", "pending"),
            datetime.utcnow(),
            datetime.utcnow()
        )
        
        result = execute_query(query, params, fetch='one')
        
        if result:
            # Normaliser les IDs pour compatibilité
            result['id'] = str(result['id'])
            result['user_id'] = str(result['user_id'])
            return result
        
        return None
        
    except Exception as e:
        logger.error(f"Erreur lors de la création de la réunion: {e}")
        raise

def get_meeting(meeting_id: str, user_id: str = None) -> Optional[Dict[str, Any]]:
    """Récupérer une réunion par ID"""
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
        logger.error(f"Erreur lors de la récupération de la réunion {meeting_id}: {e}")
        raise

def update_meeting(meeting_id: str, user_id: str, update_data: Dict[str, Any]) -> bool:
    """Mettre à jour une réunion"""
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
        logger.error(f"Erreur lors de la mise à jour de la réunion {meeting_id}: {e}")
        raise

def get_meetings_by_user(user_id: str, limit: int = None) -> List[Dict[str, Any]]:
    """Récupérer toutes les réunions d'un utilisateur"""
    try:
        query = "SELECT * FROM meetings WHERE user_id = %s ORDER BY created_at DESC"
        params = (user_id,)
        
        if limit:
            query += " LIMIT %s"
            params = (user_id, limit)
        
        meetings = execute_query(query, params, fetch='all')
        
        # Normaliser les résultats
        for meeting in meetings:
            meeting['id'] = str(meeting['id'])
            meeting['user_id'] = str(meeting['user_id'])
            
            # Convertir metadata si nécessaire
            if meeting.get('metadata') and isinstance(meeting['metadata'], str):
                try:
                    meeting['metadata'] = json.loads(meeting['metadata'])
                except:
                    pass
        
        return meetings
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des réunions pour l'utilisateur {user_id}: {e}")
        return []

def get_meetings_by_status(status: str) -> List[Dict[str, Any]]:
    """Récupérer les réunions par statut de transcription"""
    try:
        query = "SELECT * FROM meetings WHERE transcript_status = %s ORDER BY created_at"
        meetings = execute_query(query, (status,), fetch='all')
        
        # Normaliser les résultats
        for meeting in meetings:
            meeting['id'] = str(meeting['id'])
            meeting['user_id'] = str(meeting['user_id'])
        
        return meetings
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des réunions avec le statut {status}: {e}")
        return []

def get_pending_transcriptions() -> List[Dict[str, Any]]:
    """Récupérer les transcriptions en attente"""
    return get_meetings_by_status('pending')

def delete_meeting(meeting_id: str, user_id: str = None) -> bool:
    """Supprimer une réunion"""
    try:
        if user_id:
            query = "DELETE FROM meetings WHERE id = %s AND user_id = %s"
            params = (meeting_id, user_id)
        else:
            query = "DELETE FROM meetings WHERE id = %s"
            params = (meeting_id,)
        
        rowcount = execute_query(query, params)
        return rowcount > 0
        
    except Exception as e:
        logger.error(f"Erreur lors de la suppression de la réunion {meeting_id}: {e}")
        raise

# =============================================================================
# FONCTIONS DE GESTION DES LOCUTEURS
# =============================================================================

def get_meeting_speakers(meeting_id: str, user_id: str = None) -> List[Dict[str, Any]]:
    """Récupérer les locuteurs d'une réunion"""
    try:
        query = """
            SELECT s.* FROM speakers s
            JOIN meetings m ON s.meeting_id = m.id
            WHERE s.meeting_id = %s
        """
        params = [meeting_id]
        
        if user_id:
            query += " AND m.user_id = %s"
            params.append(user_id)
        
        query += " ORDER BY s.speaker_id"
        
        speakers = execute_query(query, tuple(params), fetch='all')
        
        # Normaliser les IDs
        for speaker in speakers:
            speaker['id'] = str(speaker['id'])
            speaker['meeting_id'] = str(speaker['meeting_id'])
        
        return speakers
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des locuteurs pour la réunion {meeting_id}: {e}")
        return []

def create_speaker(speaker_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Créer un nouveau locuteur"""
    try:
        query = """
            INSERT INTO speakers (meeting_id, speaker_id, custom_name, confidence, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING *
        """
        params = (
            speaker_data["meeting_id"],
            speaker_data["speaker_id"],
            speaker_data.get("custom_name"),
            speaker_data.get("confidence", 0.0),
            datetime.utcnow(),
            datetime.utcnow()
        )
        
        result = execute_query(query, params, fetch='one')
        
        if result:
            result['id'] = str(result['id'])
            result['meeting_id'] = str(result['meeting_id'])
            return result
        
        return None
        
    except Exception as e:
        logger.error(f"Erreur lors de la création du locuteur: {e}")
        raise

def update_speaker(meeting_id: str, speaker_id: str, update_data: Dict[str, Any]) -> bool:
    """Mettre à jour un locuteur"""
    try:
        set_clauses = []
        values = []
        
        for key, value in update_data.items():
            if key not in ['id', 'meeting_id', 'speaker_id', 'created_at']:
                set_clauses.append(f"{key} = %s")
                values.append(value)
        
        if not set_clauses:
            return False
        
        values.extend([datetime.utcnow(), meeting_id, speaker_id])
        
        query = f"""
            UPDATE speakers 
            SET {', '.join(set_clauses)}, updated_at = %s
            WHERE meeting_id = %s AND speaker_id = %s
        """
        
        rowcount = execute_query(query, tuple(values))
        return rowcount > 0
        
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour du locuteur {speaker_id}: {e}")
        raise

# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

def normalize_transcript_format(text: str) -> str:
    """Normaliser le format du texte de transcription"""
    if not text:
        return ""
        
    # Si le texte contient déjà des marqueurs de locuteurs au format 'Speaker X: ', on le laisse tel quel
    if "Speaker " in text and ": " in text:
        return text
        
    # Sinon, on le considère comme un texte brut d'un seul locuteur
    return f"Speaker A: {text}"

def get_user_meetings_count(user_id: str) -> int:
    """Récupérer le nombre de réunions d'un utilisateur"""
    try:
        query = "SELECT COUNT(*) as count FROM meetings WHERE user_id = %s"
        result = execute_query(query, (user_id,), fetch='one')
        return result['count'] if result else 0
    except Exception as e:
        logger.error(f"Erreur lors du comptage des réunions pour l'utilisateur {user_id}: {e}")
        return 0

def get_user_stats(user_id: str) -> Dict[str, Any]:
    """Récupérer les statistiques d'un utilisateur"""
    try:
        query = """
            SELECT 
                COUNT(*) as total_meetings,
                COUNT(CASE WHEN transcript_status = 'completed' THEN 1 END) as completed_meetings,
                COUNT(CASE WHEN summary_status = 'completed' THEN 1 END) as meetings_with_summary,
                SUM(duration_seconds) as total_duration_seconds,
                MAX(created_at) as last_meeting_date
            FROM meetings 
            WHERE user_id = %s
        """
        result = execute_query(query, (user_id,), fetch='one')
        
        if result:
            return {
                'total_meetings': result['total_meetings'] or 0,
                'completed_meetings': result['completed_meetings'] or 0,
                'meetings_with_summary': result['meetings_with_summary'] or 0,
                'total_duration_seconds': result['total_duration_seconds'] or 0,
                'last_meeting_date': result['last_meeting_date']
            }
        
        return {
            'total_meetings': 0,
            'completed_meetings': 0,
            'meetings_with_summary': 0,
            'total_duration_seconds': 0,
            'last_meeting_date': None
        }
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des statistiques pour l'utilisateur {user_id}: {e}")
        return {}

# =============================================================================
# COMPATIBILITY LAYER - Ancien code SQLite
# =============================================================================

# Fonctions de compatibilité pour l'ancien code qui utilisait SQLite
def insert_meeting(*args, **kwargs):
    """Fonction de compatibilité - utilisez create_meeting()"""
    logger.warning("insert_meeting() est déprécié, utilisez create_meeting()")
    return create_meeting(*args, **kwargs)

def get_all_meetings(user_id: str):
    """Fonction de compatibilité - utilisez get_meetings_by_user()"""
    logger.warning("get_all_meetings() est déprécié, utilisez get_meetings_by_user()")
    return get_meetings_by_user(user_id)

# =============================================================================
# FONCTIONS DE VALIDATION ET NETTOYAGE
# =============================================================================

def validate_meeting_data(meeting_data: Dict[str, Any]) -> Dict[str, Any]:
    """Valider et nettoyer les données d'une réunion"""
    validated = {}
    
    # Champs obligatoires
    if 'user_id' not in meeting_data:
        raise ValueError("user_id est obligatoire")
    
    validated['user_id'] = str(meeting_data['user_id'])
    validated['title'] = meeting_data.get('title', '').strip()
    validated['file_url'] = meeting_data.get('file_url', '').strip()
    
    # Champs optionnels avec valeurs par défaut
    validated['transcript_status'] = meeting_data.get('transcript_status', 'pending')
    validated['transcript_text'] = meeting_data.get('transcript_text')
    validated['duration_seconds'] = meeting_data.get('duration_seconds')
    validated['speakers_count'] = meeting_data.get('speakers_count')
    validated['summary_text'] = meeting_data.get('summary_text')
    validated['summary_status'] = meeting_data.get('summary_status', 'not_generated')
    
    # Nettoyer les valeurs None
    return {k: v for k, v in validated.items() if v is not None}

def clean_transcript_text(text: str) -> str:
    """Nettoyer le texte de transcription"""
    if not text:
        return ""
    
    # Supprimer les caractères de contrôle et normaliser les espaces
    import re
    text = re.sub(r'\s+', ' ', text.strip())
    
    # Supprimer les caractères non imprimables
    text = ''.join(char for char in text if char.isprintable() or char in '\n\r\t')
    
    return text

# =============================================================================
# EXPORT DU MODULE
# =============================================================================

__all__ = [
    'create_meeting',
    'get_meeting', 
    'update_meeting',
    'get_meetings_by_user',
    'get_meetings_by_status',
    'get_pending_transcriptions',
    'delete_meeting',
    'get_meeting_speakers',
    'create_speaker',
    'update_speaker',
    'normalize_transcript_format',
    'get_user_meetings_count',
    'get_user_stats',
    'validate_meeting_data',
    'clean_transcript_text'
]