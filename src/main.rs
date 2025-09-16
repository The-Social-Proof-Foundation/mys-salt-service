use anyhow::{Context, Result};
use axum::{
    Router,
    routing::{get, post},
    http::{header, Method},
};
use base64::{Engine as _, engine::general_purpose};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::signal;
use tower_http::{
    cors::CorsLayer,
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use mys_salt_service::{
    config::Config,
    db::SaltStore,
    monitoring::Metrics,
    state::AppState,
    security::{SaltManager, jwt::JwtValidator},
};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting the MySocial Salt Service");

    // Load configuration
    let config = Config::from_env()?;
    config.validate()?;

    let config = Arc::new(config);
    info!("Configuration loaded successfully");

    // Decode master seed
    let master_seed = general_purpose::STANDARD
        .decode(&config.master_seed_base64)
        .context("Failed to decode master seed")?;

    // Initialize components
    let store = SaltStore::new(&config.database_url).await?;
    info!("Database connection established");

    // Run migrations
    run_migrations(&store).await?;
    info!("Database migrations completed");

    let salt_manager = Arc::new(SaltManager::new(master_seed)?);
    let jwt_validator = Arc::new(JwtValidator::new());
    let metrics = Arc::new(Metrics::new());

    let state = AppState {
        config: config.clone(),
        store,
        salt_manager,
        jwt_validator,
        metrics,
    };

    // Build router
    let app = build_router(state.clone(), &config.allowed_origins);

    // Start background tasks
    tokio::spawn(cleanup_task(state.store.clone()));

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn build_router(state: AppState, allowed_origins: &[String]) -> Router {
    // CORS configuration
    let cors = CorsLayer::new()
        .allow_origin(
            allowed_origins
                .iter()
                .map(|o| o.parse().unwrap())
                .collect::<Vec<_>>(),
        )
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);

    Router::new()
        .route("/health", get(mys_salt_service::handlers::health_check))
        .route("/salt", post(mys_salt_service::handlers::get_salt))
        .route("/salt/test", post(mys_salt_service::handlers::get_salt_test))
        .route("/metrics", get(mys_salt_service::handlers::get_metrics))
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(1024 * 1024)) // 1MB limit
        .layer(cors)
        .layer(TraceLayer::new_for_http())
}

async fn run_migrations(store: &SaltStore) -> Result<()> {
    sqlx::migrate!("./migrations")
        .run(store.pool())
        .await
        .context("Failed to run migrations")?;
    Ok(())
}

async fn cleanup_task(store: SaltStore) {
    let mut interval = tokio::time::interval(Duration::from_secs(3600)); // 1 hour
    
    loop {
        interval.tick().await;
        
        match store.cleanup_rate_limits(24).await {
            Ok(count) => {
                if count > 0 {
                    info!("Cleaned up {} old rate limit entries", count);
                }
            }
            Err(e) => {
                error!("Failed to cleanup rate limits: {}", e);
            }
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received");
}
