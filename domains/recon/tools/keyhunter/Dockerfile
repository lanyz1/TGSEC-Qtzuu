# Build stage
FROM rust:bookworm as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY Cargo.toml ./
COPY src ./src

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/keyhunter /usr/local/bin/keyhunter

# Create results directory
RUN mkdir -p /app/results

# Copy example config
COPY config.toml.example /app/config.toml.example

# Set default config location
VOLUME ["/app/config.toml", "/app/results"]

ENTRYPOINT ["keyhunter"]
CMD ["--help"]