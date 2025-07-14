# Bug Report for MySocial Salt Service

## Critical Issues

### 1. Panic-inducing unwrap() calls
Multiple locations in the codebase use `.unwrap()` or `.expect()` which can cause the application to panic and crash:

- **src/main.rs:110** - CORS configuration will panic if `allowed_origins` contains invalid URLs:
  ```rust
  .map(|o| o.parse().unwrap())
  ```
  
- **src/main.rs:158,164** - Signal handlers use `.expect()` which could panic:
  ```rust
  .expect("failed to install Ctrl+C handler");
  .expect("failed to install signal handler")
  ```

- **src/handlers/mod.rs:22** - BN254 modulus parsing could theoretically panic:
  ```rust
  .expect("Failed to parse BN254 modulus");
  ```

- **src/security/jwt.rs:61** - HTTP client builder could panic:
  ```rust
  .expect("Failed to build HTTP client"),
  ```

### 2. Security Vulnerabilities

#### Test Endpoint Security (src/handlers/mod.rs:222-300)
- The test endpoint (`/salt/test`) relies on an environment variable check that could be bypassed
- Uses `.unwrap_or_default()` on ENVIRONMENT check, which returns empty string if not set
- Should use a more secure method or remove from production builds entirely

#### Missing Input Validation
- **src/config.rs** - No validation for:
  - Port range (could be > 65535)
  - Rate limit could be negative
  - Allowed origins URLs are not validated before use

## High Priority Issues

### 3. Configuration Issues

#### src/config.rs
- `rate_limit_per_minute` is i32 but should be u32 (negative values don't make sense)
- No upper bound validation on port number
- No validation that allowed_origins are valid URLs before they're used

### 4. Error Handling Issues

#### Ignored Errors
- **src/handlers/mod.rs** - Multiple instances of ignored errors with `let _`:
  - Line 107: `let _ = state.store.log_audit(...)`
  - Line 152: `let _ = state.store.log_audit(...)`
  - Line 75: `let _ = state.store.log_audit(...)`
  
  These audit log failures should at least be logged

### 5. Resource Management

#### src/main.rs
- Cleanup task runs every hour regardless of load - could be optimized
- No graceful shutdown for background tasks
- Database connection pool size (20) is hardcoded - should be configurable

## Medium Priority Issues

### 6. Database Schema Issues

#### migrations/002_change_ip_to_text.sql
- Changing from INET to TEXT loses IP validation at database level
- No migration rollback script provided
- Could allow invalid IP addresses to be stored

### 7. Monitoring and Observability

#### src/monitoring.rs
- Uses `Ordering::Relaxed` for all atomic operations - might miss some counts under high concurrency
- No histogram or percentile metrics for response times
- No metrics for database query performance

### 8. JWT Validation

#### src/security/jwt.rs
- JWKS cache duration is hardcoded to 1 hour - should be configurable
- No retry logic for failed JWKS fetches
- Timeout is hardcoded to 10 seconds

## Low Priority Issues

### 9. Code Quality

#### General
- Magic numbers throughout the code (3600 for cache duration, 24 for cleanup hours)
- Inconsistent error messages - some are capitalized, others aren't
- `.DS_Store` file is committed to the repository

### 10. Testing

#### src/security/mod.rs
- Tests use `.unwrap()` which could make test failures harder to debug
- No integration tests visible
- No load testing or performance benchmarks

## Recommendations

1. **Replace all `.unwrap()` and `.expect()` calls** with proper error handling
2. **Add comprehensive input validation** for all configuration values
3. **Implement proper error logging** for audit trail failures
4. **Add rate limiting validation** to prevent negative or extremely high values
5. **Secure or remove the test endpoint** from production builds
6. **Add database migration rollback scripts**
7. **Make hardcoded values configurable** (timeouts, cache durations, pool sizes)
8. **Add retry logic** for external service calls (JWKS fetching)
9. **Implement proper metrics** with histograms and percentiles
10. **Add comprehensive integration tests**

## Security Recommendations

1. Consider adding request signing/HMAC validation for additional security
2. Implement API key authentication for the metrics endpoint
3. Add IP allowlisting for sensitive endpoints
4. Consider implementing circuit breakers for external service calls
5. Add more detailed audit logging for security events