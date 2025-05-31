 # MySocial Salt Service

A production-ready salt backup service for zkLogin, based on [Mysten Labs architecture](https://blog.sui.io/zklogin-salt-server-architecture/).

## Overview

This service provides secure salt generation and storage for zkLogin authentication, ensuring that:
- User identities remain private and cannot be traced back to Web2 credentials
- Salts are deterministically generated per user per app
- All operations are audited and rate-limited
- Data is encrypted at rest

## Features

- **Secure Salt Generation**: Deterministic salt generation using SHA-256 with domain separation
- **Encryption at Rest**: ChaCha20-Poly1305 encryption for stored salts
- **JWT Validation**: Support for Google and Facebook OAuth providers
- **Rate Limiting**: IP-based rate limiting to prevent abuse
- **Audit Logging**: Comprehensive audit trail for all operations
- **Health Monitoring**: Built-in health checks and metrics endpoints
- **Production Ready**: Graceful shutdown, structured logging, and error handling

## Architecture

```
┌─────────────┐     JWT      ┌──────────────┐
│   Client    │─────────────▶│ Salt Service │
└─────────────┘              └──────┬───────┘
                                    │
                              ┌─────▼───────┐
                              │  PostgreSQL │
                              └─────────────┘
```

## Setup

### Prerequisites

- Rust 1.70+
- PostgreSQL 14+
- Railway account (for deployment)

### Local Development

1. **Clone the repository**
   ```bash
   cd mys-salt-service
   ```

2. **Generate a master seed**
   ```bash
   cargo run --bin generate_seed
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Run database migrations**
   ```bash
   cargo sqlx migrate run
   ```

5. **Start the service**
   ```bash
   cargo run
   ```

## Deployment on Railway

### 1. Create Railway Project

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login to Railway
railway login

# Create new project
railway init
```

### 2. Add PostgreSQL Database

In Railway dashboard:
1. Click "New Service"
2. Select "Database" → "PostgreSQL"
3. Note the connection string

### 3. Configure Environment Variables

Set these in Railway dashboard:

```bash
DATABASE_URL=<your-postgresql-url>
MASTER_SEED=<base64-encoded-seed>
PORT=8080
ALLOWED_ORIGINS=https://wallet.mysocial.network
RATE_LIMIT=60
LOG_LEVEL=info
```

### 4. Deploy

```bash
railway up
```

## API Endpoints

### POST /salt
Get or create salt for a user.

Request:
```json
{
  "jwt": "eyJhbGciOiJSUzI1NiIs..."
}
```

Response:
```json
{
  "salt": "base64-encoded-salt"
}
```

### GET /health
Health check endpoint.

Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00Z",
  "version": "0.1.0"
}
```

### GET /metrics
Service metrics (consider protecting this endpoint in production).

Response:
```json
{
  "requests_total": 1000,
  "requests_success": 950,
  "requests_failed": 50,
  "jwt_validations_failed": 30,
  "salts_created": 100,
  "salts_retrieved": 850,
  "rate_limits_hit": 20,
  "uptime_seconds": 86400,
  "start_time": "2024-01-01T00:00:00Z"
}
```

## Security Considerations

1. **Master Seed Protection**
   - Store in Railway's encrypted environment variables
   - Never commit to version control
   - Use different seeds for dev/staging/production
   - Rotate every 90 days

2. **Database Security**
   - Enable SSL/TLS connections
   - Use connection pooling
   - Regular backups

3. **Network Security**
   - HTTPS only in production
   - Strict CORS policies
   - Rate limiting per IP

4. **Monitoring**
   - Set up alerts for failed JWT validations
   - Monitor rate limit violations
   - Track salt creation patterns

## Recovery Procedures

### Master Seed Recovery
1. Keep encrypted backup of master seed in secure storage
2. Document recovery process with multiple approvers
3. Test recovery quarterly

### Database Recovery
- Railway provides automatic daily backups
- Point-in-time recovery available
- Test restore procedures regularly

## Performance

- Handles 1000+ requests/second
- Sub-10ms response time for cached salts
- Automatic connection pooling
- Efficient rate limiting with database cleanup

## Monitoring

Set up monitoring for:
- Service uptime
- Response times
- Error rates
- Database connections
- Rate limit violations

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new features
4. Ensure all tests pass
5. Submit pull request

## License

[Your License Here]