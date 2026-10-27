FROM rust:1.99-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN groupadd --gid 10001 www && useradd --uid 10001 --gid www --create-home www
COPY --from=builder /src/target/release/www /usr/local/bin/www
USER www
WORKDIR /srv
EXPOSE 8000
ENTRYPOINT ["www"]
