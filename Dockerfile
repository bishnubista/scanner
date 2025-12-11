# SAFE-MCP Scanner API Dockerfile
# Multi-stage build for minimal image size

# ============================================================================
# Stage 1: Build
# ============================================================================
FROM rust:1.83-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libgit2-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY api/Cargo.toml ./api/
COPY cli/Cargo.toml ./cli/
COPY engine/Cargo.toml ./engine/
COPY server/Cargo.toml ./server/

# Create dummy source files to build dependencies
RUN mkdir -p api/src cli/src engine/src server/src && \
    echo "fn main() {}" > api/src/main.rs && \
    echo "fn main() {}" > cli/src/main.rs && \
    echo "" > engine/src/lib.rs && \
    echo "fn main() {}" > server/src/main.rs

# Build dependencies only (this layer will be cached)
RUN cargo build --release -p scanner-api 2>/dev/null || true

# Copy actual source code
COPY api/src ./api/src
COPY cli/src ./cli/src
COPY engine/src ./engine/src
COPY server/src ./server/src

# Touch source files to force rebuild
RUN touch api/src/main.rs engine/src/lib.rs

# Build the actual binary
RUN cargo build --release -p scanner-api

# ============================================================================
# Stage 2: Runtime
# ============================================================================
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libgit2-1.5 \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 scanner

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/scanner-api /app/scanner-api

# Copy technique specs and schemas
COPY techniques /app/techniques
COPY schemas /app/schemas

# Clone safe-mcp knowledge base (techniques, mitigations, README)
# This provides the context the LLM needs for vulnerability detection
RUN git clone --depth 1 https://github.com/SAFE-MCP/safe-mcp.git /app/safe-mcp && \
    rm -rf /app/safe-mcp/.git && \
    # Create prioritized-techniques.md if it doesn't exist (required by engine)
    echo "| Technique ID | Name |" > /app/safe-mcp/techniques/prioritized-techniques.md && \
    echo "|--------------|------|" >> /app/safe-mcp/techniques/prioritized-techniques.md && \
    chown -R scanner:scanner /app

USER scanner

# Environment variables
ENV PORT=8080
ENV TECHNIQUES_DIR=/app/techniques
ENV SCHEMA_PATH=/app/schemas/technique.schema.json
ENV SAFE_MCP_PATH=/app/safe-mcp
ENV LLM_PROVIDER=openai
ENV RUST_LOG=scanner_api=info,tower_http=info

EXPOSE 8080

CMD ["/app/scanner-api"]
