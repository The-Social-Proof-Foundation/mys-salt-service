# zkLogin Salt Backup Service Implementation Plan

## Executive Summary

This document outlines our plan to implement a salt backup service for zkLogin based on [Mysten Labs architecture](https://blog.sui.io/zklogin-salt-server-architecture/), but adapted for our scale and requirements.

## Key Decision: Railway vs AWS Nitro Enclaves

While Mysten Labs uses AWS Nitro Enclaves for enterprise-grade security, we can use Railway for our implementation because:

1. **Scale**: We are not managing millions of users yet
2. **Cost**: AWS Nitro Enclaves would be overkill for our current needs
3. **Complexity**: Railway provides sufficient security with less operational overhead
4. **Budget**: Railway implementation costs ~-40/month vs s/month for AWS

## Implementation Plan

### Phase 1: Basic Setup (Week 1)
- Set up PostgreSQL on Railway
- Implement basic salt generation service
- Add JWT validation for OAuth providers
- Deploy initial version

### Phase 2: Security (Week 2)
- Implement master seed management
- Add encryption for sensitive data
- Set up audit logging
- Configure backups

### Phase 3: Integration (Week 3)
- Connect with zkLogin verifier
- Add monitoring and alerts
- Implement rate limiting
- Add health checks

### Phase 4: Production (Week 4)
- Security audit
- Load testing
- Documentation
- Disaster recovery planning

## Technical Architecture

### Database Schema
```sql
CREATE TABLE user_salts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_identifier VARCHAR(255) NOT NULL UNIQUE,
    iss VARCHAR(255) NOT NULL,
    aud VARCHAR(255) NOT NULL,
    sub VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_user_lookup ON user_salts (iss, aud, sub);
```

### Environment Variables
```bash
MASTER_SEED=<secure-random-seed>
DATABASE_URL=postgresql://...
ALLOWED_ORIGINS=https://wallet.mysocial.network
JWT_TIMEOUT=30
RATE_LIMIT=60
```

## Security Measures

1. **Master Seed Protection**
   - Stored in Railway encrypted environment variables
   - Different seeds per environment
   - Regular rotation schedule

2. **Database Security**
   - Encrypted at rest
   - TLS connections
   - Regular backups

3. **Network Security**
   - TLS 1.3
   - Rate limiting
   - CORS policies

4. **Monitoring**
   - Request logging
   - Error alerting
   - Performance metrics

## Cost Breakdown

### Development
- Railway PostgreSQL: /month
- Railway Web Service: /month
- Total: /month

### Production
- Railway PostgreSQL Pro: /month
- Railway Web Service Pro: /month
- Total: /month

## Next Steps

1. Create new Railway project
2. Set up PostgreSQL database
3. Initialize Rust project with required dependencies
4. Begin Phase 1 implementation




## Salt Security Implementation

### 1. Salt Generation and Encryption
```rust
pub struct SaltManager {
    master_seed: Vec<u8>,
    encryption_key: Key,
}

impl SaltManager {
    // Generate deterministic salt from JWT claims
    pub fn generate_salt(&self, claims: &JwtClaims) -> Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        
        // Domain separation
        hasher.update(b"MYSOCIAL_SALT_V1");
        hasher.update(&self.master_seed);
        hasher.update(claims.iss.as_bytes());
        hasher.update(claims.aud.as_bytes());
        hasher.update(claims.sub.as_bytes());
        
        Ok(hasher.finalize().to_vec())
    }
    
    // Encrypt salt for storage
    pub fn encrypt_salt(&self, salt: &[u8]) -> Result<Vec<u8>> {
        let nonce = generate_nonce();
        let cipher = ChaCha20Poly1305::new(&self.encryption_key);
        
        let mut encrypted = nonce.to_vec();
        encrypted.extend_from_slice(&cipher.encrypt(&nonce, salt)?);
        
        Ok(encrypted)
    }
}
```

### 2. Updated Database Schema
```sql
-- Update user_salts table to store encrypted data
ALTER TABLE user_salts
    ADD COLUMN encrypted_salt BYTEA,
    ADD COLUMN encryption_version INT NOT NULL DEFAULT 1;

-- Add audit logging
CREATE TABLE salt_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_identifier VARCHAR(255) NOT NULL,
    action_type VARCHAR(50) NOT NULL,  -- CREATE, READ, ROTATE
    ip_address INET,
    user_agent TEXT,
    jwt_hash VARCHAR(255),             -- Hash of JWT for auditing
    success BOOLEAN DEFAULT true,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_user ON salt_audit_log (user_identifier);
CREATE INDEX idx_audit_time ON salt_audit_log (created_at);
```

### 3. Security Flow
```rust
async fn handle_get_salt(jwt: &str) -> Result<String> {
    // 1. Validate JWT
    let claims = jwt_validator.validate(jwt).await?;
    
    // 2. Generate or retrieve salt
    let salt = match store.get_salt(&claims).await? {
        Some(existing) => {
            audit_log.record("READ", &claims, true);
            existing
        }
        None => {
            let new_salt = salt_manager.generate_salt(&claims)?;
            let encrypted = salt_manager.encrypt_salt(&new_salt)?;
            store.store_encrypted_salt(&claims, &encrypted).await?;
            audit_log.record("CREATE", &claims, true);
            new_salt
        }
    };
    
    Ok(base64::encode(salt))
}
```

### 4. Key Security Measures

1. **Salt Storage Protection**
   - ✅ Salts never stored in plaintext
   - ✅ ChaCha20-Poly1305 encryption at rest
   - ✅ Encryption key separate from master seed
   - ✅ Support for key rotation
   - ✅ Comprehensive audit logging

2. **Master Seed Management**
   - ✅ Stored only in Railway environment variables
   - ✅ Never logged or exposed
   - ✅ Different seeds per environment
   - ✅ 90-day rotation schedule
   - ✅ Backup recovery procedure

3. **Access Controls**
   - ✅ JWT validation required for all operations
   - ✅ Rate limiting per IP and per user
   - ✅ CORS restrictions to allowed origins
   - ✅ Input validation and sanitization
   - ✅ Request logging and monitoring

### 5. Monitoring and Alerts

```rust
pub struct SecurityMonitor {
    // Alert thresholds
    max_failed_attempts: u32,
    max_requests_per_minute: u32,
    suspicious_ip_threshold: u32,
    
    // Alert channels
    alert_email: String,
    slack_webhook: Option<String>,
}

impl SecurityMonitor {
    pub async fn check_thresholds(&self) {
        // Monitor failed attempts
        let failed = audit_log
            .count_failed_attempts(Duration::minutes(5))
            .await?;
        
        if failed > self.max_failed_attempts {
            self.send_alert("High number of failed attempts detected").await?;
        }
        
        // Monitor request rates
        let rpm = metrics
            .requests_per_minute()
            .await?;
            
        if rpm > self.max_requests_per_minute {
            self.send_alert("Request rate threshold exceeded").await?;
        }
    }
}
```

### 6. Recovery Procedures

1. **Master Seed Loss**
   - Keep encrypted backup in secure storage
   - Require multiple approvers for recovery
   - Document step-by-step recovery process
   - Test recovery quarterly

2. **Database Recovery**
   - Automated daily backups
   - Point-in-time recovery enabled
   - Regular restore testing
   - Cross-region backup copies

3. **Security Incident**
   - Incident response playbook
   - Ability to rotate all keys
   - User notification process
   - Post-mortem procedures