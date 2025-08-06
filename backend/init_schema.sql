-- =============================================================================
-- SCHÉMA POSTGRESQL UNIFIÉ POUR GILBERT
-- Version de production - Compatible avec la migration SQLite
-- =============================================================================

-- Création des extensions nécessaires
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- =============================================================================
-- TABLE DES UTILISATEURS
-- =============================================================================

-- Supprimer la table si elle existe (pour migration propre)
-- DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    profile_picture_url TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    oauth_provider VARCHAR(50),
    oauth_id VARCHAR(255),
    UNIQUE(oauth_provider, oauth_id)
);

-- =============================================================================
-- TABLE DES RÉUNIONS
-- =============================================================================

-- Supprimer la table si elle existe (pour migration propre)
-- DROP TABLE IF EXISTS meetings CASCADE;

CREATE TABLE IF NOT EXISTS meetings (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    file_url TEXT,  -- Chemin vers le fichier audio
    transcript_text TEXT,  -- Texte de la transcription
    transcript_status VARCHAR(50) DEFAULT 'pending',  -- pending, processing, completed, error
    transcript_id VARCHAR(255),  -- ID AssemblyAI pour suivi
    duration_seconds INTEGER,  -- Durée en secondes
    speakers_count INTEGER,  -- Nombre de locuteurs
    summary_text TEXT,  -- Texte du résumé
    summary_status VARCHAR(50) DEFAULT 'not_generated',  -- not_generated, processing, completed, error
    client_id INTEGER,  -- Référence vers un client (optionnel)
    metadata JSONB,  -- Métadonnées additionnelles
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP WITH TIME ZONE  -- Quand la transcription a été terminée
);

-- =============================================================================
-- TABLE DES LOCUTEURS (SPEAKERS)
-- =============================================================================

CREATE TABLE IF NOT EXISTS speakers (
    id SERIAL PRIMARY KEY,
    meeting_id INTEGER REFERENCES meetings(id) ON DELETE CASCADE,
    speaker_id VARCHAR(10) NOT NULL,  -- A, B, C, D, etc.
    custom_name VARCHAR(255),  -- Nom personnalisé attribué par l'utilisateur
    confidence FLOAT DEFAULT 0.0,  -- Niveau de confiance de la détection
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(meeting_id, speaker_id)
);

-- =============================================================================
-- TABLE DES CLIENTS (OPTIONNEL)
-- =============================================================================

CREATE TABLE IF NOT EXISTS clients (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    phone VARCHAR(50),
    company VARCHAR(255),
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- TABLE DES TEMPLATES DE RÉSUMÉ
-- =============================================================================

CREATE TABLE IF NOT EXISTS summary_templates (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    template_content TEXT NOT NULL,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- INDEX POUR OPTIMISER LES PERFORMANCES
-- =============================================================================

-- Index principaux
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_oauth ON users(oauth_provider, oauth_id);

CREATE INDEX IF NOT EXISTS idx_meetings_user_id ON meetings(user_id);
CREATE INDEX IF NOT EXISTS idx_meetings_status ON meetings(transcript_status);
CREATE INDEX IF NOT EXISTS idx_meetings_created_at ON meetings(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_meetings_transcript_id ON meetings(transcript_id);

CREATE INDEX IF NOT EXISTS idx_speakers_meeting_id ON speakers(meeting_id);
CREATE INDEX IF NOT EXISTS idx_speakers_speaker_id ON speakers(speaker_id);

CREATE INDEX IF NOT EXISTS idx_clients_user_id ON clients(user_id);

CREATE INDEX IF NOT EXISTS idx_templates_user_id ON summary_templates(user_id);

-- Index de recherche textuelle
CREATE INDEX IF NOT EXISTS idx_meetings_title_gin ON meetings USING gin(title gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_meetings_transcript_gin ON meetings USING gin(transcript_text gin_trgm_ops);

-- =============================================================================
-- FONCTIONS ET TRIGGERS
-- =============================================================================

-- Fonction pour mettre à jour automatiquement updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers pour mettre à jour automatiquement updated_at
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_meetings_updated_at ON meetings;
CREATE TRIGGER update_meetings_updated_at BEFORE UPDATE ON meetings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_speakers_updated_at ON speakers;
CREATE TRIGGER update_speakers_updated_at BEFORE UPDATE ON speakers
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_clients_updated_at ON clients;
CREATE TRIGGER update_clients_updated_at BEFORE UPDATE ON clients
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_templates_updated_at ON summary_templates;
CREATE TRIGGER update_templates_updated_at BEFORE UPDATE ON summary_templates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- DONNÉES INITIALES
-- =============================================================================

-- Insertion d'un utilisateur admin par défaut (mot de passe: admin123)
INSERT INTO users (email, password_hash, first_name, last_name, is_admin, is_active)
VALUES (
    'admin@gilbert.com',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.i8mG',
    'Admin',
    'Gilbert',
    TRUE,
    TRUE
) ON CONFLICT (email) DO UPDATE SET
    password_hash = EXCLUDED.password_hash,
    updated_at = CURRENT_TIMESTAMP;

-- Insertion d'un utilisateur test (mot de passe: test123)
INSERT INTO users (email, password_hash, first_name, last_name, is_active)
VALUES (
    'test@gilbert.com',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.i8mG',
    'Test',
    'User',
    TRUE
) ON CONFLICT (email) DO UPDATE SET
    password_hash = EXCLUDED.password_hash,
    updated_at = CURRENT_TIMESTAMP;

-- Template de résumé par défaut
INSERT INTO summary_templates (user_id, name, template_content, is_default)
VALUES (
    1,  -- Admin user
    'Résumé standard',
    '# Résumé de réunion

## Participants
{participants}

## Points clés abordés
{key_points}

## Décisions prises
{decisions}

## Actions à entreprendre
{action_items}

## Prochaines étapes
{next_steps}',
    TRUE
) ON CONFLICT DO NOTHING;

-- =============================================================================
-- VUES UTILES
-- =============================================================================

-- Vue pour les réunions avec informations utilisateur
CREATE OR REPLACE VIEW meetings_with_user AS
SELECT 
    m.*,
    u.email as user_email,
    u.first_name,
    u.last_name,
    CONCAT(u.first_name, ' ', u.last_name) as user_full_name
FROM meetings m
JOIN users u ON m.user_id = u.id;

-- Vue pour les statistiques des utilisateurs
CREATE OR REPLACE VIEW user_stats AS
SELECT 
    u.id,
    u.email,
    u.first_name,
    u.last_name,
    COUNT(m.id) as total_meetings,
    COUNT(CASE WHEN m.transcript_status = 'completed' THEN 1 END) as completed_meetings,
    COUNT(CASE WHEN m.summary_status = 'completed' THEN 1 END) as meetings_with_summary,
    SUM(m.duration_seconds) as total_duration_seconds,
    MAX(m.created_at) as last_meeting_date
FROM users u
LEFT JOIN meetings m ON u.id = m.user_id
GROUP BY u.id, u.email, u.first_name, u.last_name;

-- =============================================================================
-- COMMENTAIRES ET DOCUMENTATION
-- =============================================================================

COMMENT ON TABLE users IS 'Table des utilisateurs de l''application Gilbert';
COMMENT ON TABLE meetings IS 'Table des réunions et transcriptions';
COMMENT ON TABLE speakers IS 'Table des locuteurs identifiés dans les réunions';
COMMENT ON TABLE clients IS 'Table des clients pour personnalisation des templates';
COMMENT ON TABLE summary_templates IS 'Templates pour la génération de résumés';

COMMENT ON COLUMN meetings.transcript_status IS 'Statut de la transcription: pending, processing, completed, error';
COMMENT ON COLUMN meetings.summary_status IS 'Statut du résumé: not_generated, processing, completed, error';
COMMENT ON COLUMN meetings.transcript_id IS 'ID de suivi AssemblyAI pour la transcription';
COMMENT ON COLUMN speakers.speaker_id IS 'Identifiant du locuteur (A, B, C, etc.)';
COMMENT ON COLUMN speakers.custom_name IS 'Nom personnalisé attribué par l''utilisateur';

-- =============================================================================
-- VÉRIFICATIONS FINALES
-- =============================================================================

-- Vérifier que toutes les tables ont été créées
DO $$
DECLARE
    table_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO table_count
    FROM information_schema.tables
    WHERE table_schema = 'public' 
    AND table_name IN ('users', 'meetings', 'speakers', 'clients', 'summary_templates');
    
    IF table_count = 5 THEN
        RAISE NOTICE 'Toutes les tables ont été créées avec succès (% tables)', table_count;
    ELSE
        RAISE WARNING 'Seulement % tables créées sur 5 attendues', table_count;
    END IF;
END $$;

RAISE NOTICE 'Schéma PostgreSQL pour Gilbert initialisé avec succès';