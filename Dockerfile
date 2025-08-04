FROM ubuntu:latest as downloader

ARG RELAY_VERSION=latest
WORKDIR /app

RUN apt-get update && apt-get install -y curl tar unzip && rm -rf /var/lib/apt/lists/*

# Download relay-server if not provided
RUN set -e; \
    if [ "$RELAY_VERSION" = "latest" ]; then \
      RELAY_VERSION=$(curl -s https://api.github.com/repos/RelayCore/relay-server/releases/latest | grep tag_name | cut -d '"' -f 4); \
    fi; \
    set -x; \
    curl -L -o relay-server.tar.gz "https://github.com/RelayCore/relay-server/releases/download/${RELAY_VERSION}/relay-server_${RELAY_VERSION}_linux_amd64.zip" \
      && mkdir bin \
      && unzip relay-server.tar.gz -d bin \
      && mv bin/relay-server /app/relay-server \
      && rm -rf bin relay-server.tar.gz \
    || echo "Download failed, skipping downloader stage."

# --- Final image ---
FROM ubuntu:latest

ARG LOCAL_RELAY_PATH
WORKDIR /app

RUN apt-get update && apt-get install -y curl tar unzip && rm -rf /var/lib/apt/lists/*

COPY config.yaml .
RUN mkdir -p /app/uploads

# If LOCAL_RELAY_PATH exists, copy it; otherwise, copy from downloader stage
COPY ${LOCAL_RELAY_PATH:-nonexistent} /app/relay-server
# If the above fails, fallback to the downloaded binary
COPY --from=downloader /app/relay-server /app/relay-server

RUN chmod +x /app/relay-server || true

EXPOSE 36954
CMD ["./relay-server"]