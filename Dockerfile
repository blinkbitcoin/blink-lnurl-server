FROM clux/muslrust:stable AS build

RUN apt-get update && \
    apt-get install -y --no-install-recommends protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

ENV PROTOC_INCLUDE=/usr/include
ENV SQLX_OFFLINE=true

ARG CARGO_FEATURES=""
RUN if [ -z "${CARGO_FEATURES}" ]; then \
        cargo build --locked --release --bin lnurl-server; \
    else \
        cargo build --locked --release --bin lnurl-server --features "${CARGO_FEATURES}"; \
    fi && \
    find target -name lnurl-server -type f -executable && \
    cp "$(find target -name lnurl-server -type f -executable | head -1)" /tmp/lnurl-server

FROM ubuntu:24.04

COPY --from=build /tmp/lnurl-server /usr/local/bin/lnurl-server

RUN mkdir /lnurl && chown 1000:1000 /lnurl

USER 1000
WORKDIR /lnurl
CMD ["lnurl-server"]
