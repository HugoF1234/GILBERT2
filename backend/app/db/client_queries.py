# Module client queries - Compatible avec l'ancien système
from .queries import *

def create_client(client_data):
    """Créer un client"""
    # TODO: Implémenter si nécessaire
    return {"id": "1", "name": client_data.get("name", "")}

def get_client(client_id, user_id=None):
    """Récupérer un client par ID"""
    return None

def get_clients(user_id):
    """Récupérer tous les clients d'un utilisateur"""
    return []

def update_client(client_id, user_id, update_data):
    """Mettre à jour un client"""
    return True

def delete_client(client_id, user_id=None):
    """Supprimer un client"""
    return True