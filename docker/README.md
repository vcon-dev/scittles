# Docker Deployment Guide

This guide provides detailed instructions for deploying Scittles using Docker.

## Table of Contents

- [Quick Start](#quick-start)
- [Production Deployment](#production-deployment)
- [Environment Variables](#environment-variables)
- [Volume Management](#volume-management)
- [Prometheus Integration](#prometheus-integration)
- [OpenTelemetry Integration](#opentelemetry-integration)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Using Docker Compose

The easiest way to run Scittles is with Docker Compose:

```bash
# Start the service
docker-compose up -d

# View logs
docker-compose logs -f scittles

# Stop the service
docker-compose down
```

### Using Docker Directly

```bash
# Build the image
docker build -t scittles:latest .

# Run the container
docker run -d \
  --name scittles \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -e SCITT_SERVICE_URL=https://your-service-url.example \
  scittles:latest
```

## Production Deployment

### Recommended Configuration

For production deployments, consider the following:

1. **Set a proper service URL:**
   ```bash
   -e SCITT_SERVICE_URL=https://transparency.yourdomain.com
   ```

2. **Use JSON logging:**
   ```bash
   -e SCITT_LOG_FORMAT=json
   ```

3. **Configure OpenTelemetry for monitoring:**
   ```bash
   -e SCITT_OTEL_EXPORTER=otlp,prometheus
   -e SCITT_OTEL_ENDPOINT=http://otel-collector:4317
   ```

4. **Persist database with proper backups:**
   ```bash
   -v /var/lib/scittles/data:/app/data
   ```

5. **Use Docker secrets or environment files for sensitive data:**
   ```bash
   --env-file .env.production
   ```

### Example Production docker-compose.yml

```yaml
version: '3.8'

services:
  scittles:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: scittles
    ports:
      - "8000:8000"
    volumes:
      - /var/lib/scittles/data:/app/data
    environment:
      - SCITT_DB_PATH=/app/data/transparency.db
      - SCITT_SERVICE_URL=https://transparency.yourdomain.com
      - SCITT_LOG_FORMAT=json
      - SCITT_LOG_LEVEL=INFO
      - SCITT_OTEL_ENABLED=true
      - SCITT_OTEL_SERVICE_NAME=scittles
      - SCITT_OTEL_EXPORTER=otlp,prometheus
      - SCITT_OTEL_ENDPOINT=http://otel-collector:4317
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/.well-known/transparency-configuration').read()"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
    restart: unless-stopped
    networks:
      - monitoring
```

## Environment Variables

### Core Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SCITT_DB_PATH` | `/app/data/transparency.db` | Path to SQLite database file |
| `SCITT_SERVICE_URL` | `https://transparency.example` | Public URL of the service (required for production) |
| `SCITT_HOST` | `0.0.0.0` | Bind address for the HTTP server |
| `SCITT_PORT` | `8000` | Port for the HTTP server |

### Observability Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SCITT_LOG_LEVEL` | `INFO` | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `SCITT_LOG_FORMAT` | `json` (Docker) | Log format: `json` or `text` |
| `SCITT_OTEL_ENABLED` | `true` | Enable OpenTelemetry instrumentation |
| `SCITT_OTEL_SERVICE_NAME` | `scittles` | Service name for OpenTelemetry traces |
| `SCITT_OTEL_EXPORTER` | `prometheus,console` | Comma-separated list: `console`, `otlp`, `prometheus` |
| `SCITT_OTEL_ENDPOINT` | - | OTLP endpoint URL (e.g., `http://otel-collector:4317`) |
| `SCITT_OTEL_HEADERS` | - | OTLP headers as comma-separated `key=value` pairs |
| `SCITT_PROMETHEUS_PORT` | `9090` | Prometheus port configuration (metrics served on main port) |

### Example Environment File

Create a `.env` file:

```bash
SCITT_SERVICE_URL=https://transparency.yourdomain.com
SCITT_LOG_LEVEL=INFO
SCITT_LOG_FORMAT=json
SCITT_OTEL_ENABLED=true
SCITT_OTEL_EXPORTER=prometheus,otlp
SCITT_OTEL_ENDPOINT=http://otel-collector:4317
```

Then use it with Docker Compose:

```bash
docker-compose --env-file .env up -d
```

## Volume Management

### Database Persistence

The database is stored in `/app/data/transparency.db` inside the container. Mount a host directory to persist data:

```bash
-v /host/path/data:/app/data
```

### Backup Strategy

1. **Regular Backups:**
   ```bash
   # Backup the database
   docker exec scittles cp /app/data/transparency.db /app/data/transparency.db.backup
   docker cp scittles:/app/data/transparency.db.backup ./backups/
   ```

2. **Automated Backups:**
   Use a cron job or scheduled task to backup the mounted volume:
   ```bash
   #!/bin/bash
   BACKUP_DIR=/backups/scittles
   DATA_DIR=/var/lib/scittles/data
   DATE=$(date +%Y%m%d_%H%M%S)
   
   cp $DATA_DIR/transparency.db $BACKUP_DIR/transparency_$DATE.db
   ```

3. **Volume Snapshots:**
   If using cloud storage, use volume snapshots for point-in-time recovery.

### Restoring from Backup

```bash
# Stop the service
docker-compose down

# Restore the database
cp ./backups/transparency.db ./data/transparency.db

# Start the service
docker-compose up -d
```

## Prometheus Integration

### Scraping Metrics

When Prometheus exporter is enabled (default), metrics are available at `/metrics`:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'scittles'
    static_configs:
      - targets: ['scittles:8000']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

### Available Metrics

The service exposes the following metrics:

- **HTTP Metrics:**
  - `http_request_total` - Total HTTP requests
  - `http_request_duration_seconds` - Request duration histogram
  - `http_error_total` - HTTP errors by status code

- **Database Metrics:**
  - `db_operation_total` - Total database operations
  - `db_operation_duration_seconds` - Database operation duration
  - `db_error_total` - Database errors

- **Merkle Tree Metrics:**
  - `merkle_tree_size` - Current tree size
  - `merkle_operation_duration_seconds` - Tree operation duration
  - `merkle_proof_generation_total` - Inclusion proofs generated

- **Receipt Metrics:**
  - `receipt_generation_total` - Receipts generated
  - `receipt_generation_duration_seconds` - Receipt generation duration
  - `receipt_error_total` - Receipt generation errors

- **Entry Metrics:**
  - `entry_registration_total` - Entries registered
  - `entry_registration_duration_seconds` - Registration duration

### Example Prometheus Setup

```yaml
version: '3.8'

services:
  scittles:
    # ... scittles configuration ...
    networks:
      - monitoring

  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
    networks:
      - monitoring

networks:
  monitoring:
    driver: bridge
```

## OpenTelemetry Integration

### Using OTLP Exporter

Configure Scittles to export traces and metrics to an OpenTelemetry Collector:

```bash
-e SCITT_OTEL_EXPORTER=otlp
-e SCITT_OTEL_ENDPOINT=http://otel-collector:4317
```

### Example OpenTelemetry Collector Setup

```yaml
version: '3.8'

services:
  scittles:
    # ... scittles configuration ...
    environment:
      - SCITT_OTEL_EXPORTER=otlp
      - SCITT_OTEL_ENDPOINT=http://otel-collector:4317
    networks:
      - monitoring

  otel-collector:
    image: otel/opentelemetry-collector:latest
    volumes:
      - ./otel-collector-config.yml:/etc/otel-collector-config.yml
    command: ["--config=/etc/otel-collector-config.yml"]
    ports:
      - "4317:4317"  # OTLP gRPC receiver
      - "4318:4318"  # OTLP HTTP receiver
    networks:
      - monitoring

networks:
  monitoring:
    driver: bridge
```

### Collector Configuration Example

```yaml
# otel-collector-config.yml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:

exporters:
  logging:
    loglevel: info
  prometheus:
    endpoint: "0.0.0.0:8889"
  jaeger:
    endpoint: jaeger:14250
    tls:
      insecure: true

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [logging, jaeger]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [logging, prometheus]
```

## Troubleshooting

### Container Won't Start

1. **Check logs:**
   ```bash
   docker-compose logs scittles
   ```

2. **Verify environment variables:**
   ```bash
   docker-compose config
   ```

3. **Check volume permissions:**
   ```bash
   ls -la ./data
   # Ensure the directory is writable
   ```

### Database Issues

1. **Check database file:**
   ```bash
   docker exec scittles ls -la /app/data/
   ```

2. **Verify database integrity:**
   ```bash
   docker exec scittles sqlite3 /app/data/transparency.db "PRAGMA integrity_check;"
   ```

3. **Reset database (WARNING: deletes all data):**
   ```bash
   docker-compose down
   rm -rf ./data/transparency.db
   docker-compose up -d
   ```

### Metrics Not Available

1. **Verify Prometheus exporter is enabled:**
   ```bash
   docker exec scittles env | grep SCITT_OTEL_EXPORTER
   ```

2. **Check metrics endpoint:**
   ```bash
   curl http://localhost:8000/metrics
   ```

3. **Check logs for errors:**
   ```bash
   docker-compose logs scittles | grep -i prometheus
   ```

### Performance Issues

1. **Monitor resource usage:**
   ```bash
   docker stats scittles
   ```

2. **Check database size:**
   ```bash
   docker exec scittles du -h /app/data/transparency.db
   ```

3. **Review logs for slow queries:**
   ```bash
   docker-compose logs scittles | grep -i "duration"
   ```

### Network Issues

1. **Verify port mapping:**
   ```bash
   docker port scittles
   ```

2. **Test connectivity:**
   ```bash
   curl http://localhost:8000/.well-known/transparency-configuration
   ```

3. **Check firewall rules:**
   Ensure port 8000 is accessible.

## Multi-Container Setup

### Example: Scittles with Prometheus and Grafana

```yaml
version: '3.8'

services:
  scittles:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
    environment:
      - SCITT_SERVICE_URL=http://localhost:8000
      - SCITT_OTEL_EXPORTER=prometheus
    networks:
      - monitoring

  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    ports:
      - "9090:9090"
    networks:
      - monitoring

  grafana:
    image: grafana/grafana:latest
    volumes:
      - grafana-data:/var/lib/grafana
    ports:
      - "3000:3000"
    networks:
      - monitoring
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin

volumes:
  prometheus-data:
  grafana-data:

networks:
  monitoring:
    driver: bridge
```

## Security Considerations

1. **Use non-root user:** The Dockerfile already runs as a non-root user (`scittles`)

2. **Limit network exposure:** Only expose necessary ports

3. **Use secrets management:** For production, use Docker secrets or external secret managers

4. **Regular updates:** Keep the base image and dependencies updated

5. **Resource limits:** Set appropriate CPU and memory limits:
   ```yaml
   deploy:
     resources:
       limits:
         cpus: '2'
         memory: 2G
   ```

6. **Read-only filesystem:** Consider mounting the filesystem as read-only except for data directory

