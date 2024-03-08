FROM rust:1.74.0-bookworm AS builder

RUN apt-get update && \
    apt-get install -y sudo git build-essential pkg-config libssl-dev cmake clang && \
    git clone --depth=1 https://github.com/orochi-network/orochimaru && \
    cd orochimaru && cargo build --release -p node

FROM debian:bookworm

ENV RUST_LOG="debug"
ENV RUST_BACKTRACE=full

COPY --from=builder /orochimaru/target/release/node /bin/orand
COPY --from=builder /orochimaru/target/release/cli /bin/orand-cli
COPY ./env /.env

WORKDIR /

CMD ["/bin/orand"]
