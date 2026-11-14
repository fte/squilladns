FROM rust:1.99.1 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y bind9-utils ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/squilladns .
EXPOSE 8085
ENV API_TOKEN=votre_token_par_docker_compose
CMD ["./squilladns"]
