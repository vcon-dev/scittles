# Stage 1: Builder
FROM python:3.12-slim as builder
WORKDIR /app

# Install build dependencies (use HTTPS for apt — HTTP blocked on this host)
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Runtime
FROM python:3.12-slim
WORKDIR /app

# Create non-root user and data directory
RUN useradd -m -u 1000 scittles && \
    mkdir -p /app/data && \
    chown -R scittles:scittles /app

# Copy installed packages from builder
COPY --from=builder /root/.local /home/scittles/.local

# Copy application code
COPY --chown=scittles:scittles src/ ./src/
COPY --chown=scittles:scittles pyproject.toml .

# Set PATH to include user local bin
ENV PATH=/home/scittles/.local/bin:$PATH

# Switch to non-root user
USER scittles

# Expose port
EXPOSE 8000

# Run the application
CMD ["python", "-m", "src.main"]

