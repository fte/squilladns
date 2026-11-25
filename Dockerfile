# Garder builder et runtime sur la même génération Debian évite les écarts
# glibc entre l’environnement de compilation et le VPS de production.
FROM rust:1.99.1-trixie AS builder
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

# Image de vérification isolée : le test lance lui-même named, rndc et l’API.
FROM builder AS bind-e2e
RUN apt-get update \
    && apt-get install -y bind9 bind9-utils ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY tests ./tests
ENV ZONES_DIR=/var/lib/squilladns/zones
CMD ["cargo", "test", "--test", "bind_e2e", "--", "--ignored", "--nocapture"]

FROM debian:trixie-slim AS dev
RUN apt-get update \
    && apt-get install -y bind9 bind9-utils bash util-linux ca-certificates tzdata \
    && groupadd --system --gid 10001 squilladns \
    && useradd --system --uid 10001 --gid squilladns \
       --home-dir /var/lib/squilladns --no-create-home squilladns \
    && mkdir -p /var/lib/squilladns/zones /var/lib/squilladns/state /run/named \
    && chown -R squilladns:squilladns /var/lib/squilladns \
    && chown bind:bind /run/named /var/cache/bind \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/squilladns /usr/local/bin/squilladns
COPY dev/named.conf /etc/bind/squilladns-dev.conf
COPY dev/rndc.conf /etc/bind/squilladns-rndc.conf
COPY dev/entrypoint.sh /usr/local/bin/squilladns-dev-entrypoint
RUN chmod 0755 /usr/local/bin/squilladns-dev-entrypoint
ENV ZONES_DIR=/var/lib/squilladns/zones \
    API_TOKEN_PATH=/var/lib/squilladns/state/tokens \
    RNDC_BIN=rndc \
    RNDC_CONF=/etc/bind/squilladns-rndc.conf
EXPOSE 8085 53/tcp 53/udp
ENTRYPOINT ["/usr/local/bin/squilladns-dev-entrypoint"]

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y bind9-utils ca-certificates tzdata \
    && groupadd --system --gid 10001 squilladns \
    && useradd --system --uid 10001 --gid squilladns \
       --home-dir /var/lib/squilladns --no-create-home squilladns \
    && mkdir -p /var/lib/squilladns/zones /var/lib/squilladns/state \
    && chown -R squilladns:squilladns /var/lib/squilladns \
    && rm -rf /var/lib/apt/lists/*
ENV ZONES_DIR=/var/lib/squilladns/zones \
    API_TOKEN_PATH=/var/lib/squilladns/state/tokens
COPY --from=builder /app/target/release/squilladns /usr/local/bin/squilladns
USER squilladns:squilladns
EXPOSE 8085
CMD ["/usr/local/bin/squilladns"]
