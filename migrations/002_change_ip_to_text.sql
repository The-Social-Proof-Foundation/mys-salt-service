-- Change ip_address column from INET to TEXT for simplicity
ALTER TABLE salt_audit_log 
    ALTER COLUMN ip_address TYPE TEXT; 