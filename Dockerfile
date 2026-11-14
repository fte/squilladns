FROM rust:1.99.1 AS builder
WORKDIR /app

# Tous les chemins temporaires dans /app — rien dans /tmp
ENV CARGO_HOME=/app/.cargo
ENV CARGO_TARGET_DIR=/app/target
ENV TMPDIR=/app/tmp
RUN mkdir -p /app/tmp

# Cache des dépendances séparé du code source
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && printf 'fn main(){}' > src/main.rs \
    && printf '' > src/zone.rs \
    && printf '' > src/auth.rs \
    && cargo build --release \
    && rm -rf src

# Compilation du code source
COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y bind9-utils ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/squilladns .
EXPOSE 8085
ENV API_TOKEN=change-me-apres-creation
CMD ["./squilladns"]
