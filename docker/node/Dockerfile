FROM rust:1.74.0-alpine3.18 AS builder

RUN apk update && apk upgrade && apk add git pkgconfig gcc cmake musl-dev && \
    git clone https://github.com/orochi-network/orochimaru && \
    cd orochimaru && cargo build --release -p node

FROM alpine:latest

COPY --from=builder /orochimaru/target/release/node /bin/orand
COPY --from=builder /orochimaru/target/release/cli /bin/orand-cli
COPY ./env /.env

WORKDIR /

CMD ["/bin/orand"]
