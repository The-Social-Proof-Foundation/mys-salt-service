#!/bin/bash

# MYS Salt Service Setup Script

set -e

echo "🚀 MYS Salt Service Setup"
echo "========================"

# Check if master seed exists
if [ -z "$MASTER_SEED" ]; then
    echo ""
    echo "⚠️  No MASTER_SEED found in environment"
    echo "Generating a new master seed..."
    echo ""
    
    cargo run --bin generate_seed
    
    echo ""
    echo "Please set the MASTER_SEED environment variable with the generated value"
    echo ""
    exit 1
fi

# Check database URL
if [ -z "$DATABASE_URL" ]; then
    echo "❌ DATABASE_URL environment variable not set"
    exit 1
fi

echo "✅ Environment variables configured"

# Run migrations
echo ""
echo "🗄️  Running database migrations..."
sqlx migrate run

echo "✅ Migrations completed"

# Build the project
echo ""
echo "🔨 Building project..."
cargo build --release

echo ""
echo "✅ Setup complete!"
echo ""
echo "To start the service:"
echo "  cargo run --release"
echo ""
echo "Or for production:"
echo "  ./target/release/mys-salt-service" 