#!/bin/bash

# Script to verify your salt service deployment

# Initialize error counter
ERRORS=0

echo "🔍 Verifying Salt Service Deployment"
echo "===================================="

# Replace with your actual Railway URL
SERVICE_URL="https://salt.testnet.mysocial.network/"

echo ""
echo "1. Testing health endpoint..."
if ! curl -s "$SERVICE_URL/health" | jq .; then
    echo "❌ Health check failed"
    ((ERRORS++))
fi

echo ""
echo "2. Testing metrics endpoint..."
if ! curl -s "$SERVICE_URL/metrics" | jq .; then
    echo "❌ Metrics check failed"
    ((ERRORS++))
fi

echo ""
echo "3. Testing salt generation with test endpoint..."
TEST_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

if ! curl -X POST "$SERVICE_URL/salt/test" \
  -H "Content-Type: application/json" \
  -d "{\"jwt\": \"$TEST_JWT\"}" | jq .; then
    echo "❌ Test endpoint failed"
    ((ERRORS++))
fi

echo ""
echo "4. To check if migrations ran, look for this in your Railway logs:"
echo "   - 'Database migrations completed'"
echo "   - 'Starting server on 0.0.0.0:3000'"
echo ""
echo "5. To verify database tables exist, you can:"
echo "   - Use Railway's database query interface"
echo "   - Run: SELECT * FROM user_salts LIMIT 1;"
echo "   - Run: SELECT * FROM salt_audit_log LIMIT 1;"

# Exit with status code based on errors
if [ $ERRORS -eq 0 ]; then
    echo -e "\n✅ All tests passed!"
    exit 0
else
    echo -e "\n❌ $ERRORS test(s) failed!"
    exit 1
fi