-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- User salts table
CREATE TABLE user_salts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_identifier VARCHAR(255) NOT NULL UNIQUE,
    iss VARCHAR(255) NOT NULL,
    aud VARCHAR(255) NOT NULL,
    sub VARCHAR(255) NOT NULL,
    encrypted_salt BYTEA NOT NULL,
    encryption_version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for efficient lookups
CREATE INDEX idx_user_lookup ON user_salts (iss, aud, sub);
CREATE INDEX idx_user_identifier ON user_salts (user_identifier);

-- Audit log table
CREATE TABLE salt_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_identifier VARCHAR(255) NOT NULL,
    action_type VARCHAR(50) NOT NULL,  -- CREATE, READ, ROTATE, ERROR
    ip_address INET,
    user_agent TEXT,
    jwt_hash VARCHAR(255),             -- Hash of JWT for auditing
    success BOOLEAN DEFAULT true,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for audit queries
CREATE INDEX idx_audit_user ON salt_audit_log (user_identifier);
CREATE INDEX idx_audit_time ON salt_audit_log (created_at);
CREATE INDEX idx_audit_action ON salt_audit_log (action_type);
CREATE INDEX idx_audit_success ON salt_audit_log (success);

-- Rate limiting table
CREATE TABLE rate_limit_entries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identifier VARCHAR(255) NOT NULL,  -- IP or user identifier
    request_count INT NOT NULL DEFAULT 1,
    window_start TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_rate_limit_identifier ON rate_limit_entries (identifier, window_start);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for user_salts
CREATE TRIGGER update_user_salts_updated_at BEFORE UPDATE
    ON user_salts FOR EACH ROW EXECUTE FUNCTION update_updated_at_column(); 
