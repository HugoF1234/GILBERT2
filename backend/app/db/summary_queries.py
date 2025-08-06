# Module summary queries - Compatible avec l'ancien système
from .queries import *

def create_summary_template(template_data):
    """Créer un template de résumé"""
    # TODO: Implémenter si nécessaire
    return {"id": "1", "name": template_data.get("name", "")}

def get_summary_template(template_id, user_id=None):
    """Récupérer un template par ID"""
    return None

def get_summary_templates(user_id):
    """Récupérer tous les templates d'un utilisateur"""
    return []

def update_summary_template(template_id, user_id, update_data):
    """Mettre à jour un template"""
    return True

def delete_summary_template(template_id, user_id=None):
    """Supprimer un template"""
    return True