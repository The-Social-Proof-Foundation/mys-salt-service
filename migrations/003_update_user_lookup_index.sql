-- Unify lookup index across platforms by using issuer + subject
-- This drops the old (iss, aud, sub) index and recreates for (iss, sub)

DROP INDEX IF EXISTS idx_user_lookup;
CREATE INDEX idx_user_lookup ON user_salts (iss, sub);

