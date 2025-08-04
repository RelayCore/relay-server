FROM ubuntu:latest

ARG RELAY_VERSION=latest
ARG LOCAL_RELAY_PATH
WORKDIR /app

RUN apt-get update && apt-get install -y curl tar unzip && rm -rf /var/lib/apt/lists/*

COPY config.yaml .
RUN mkdir -p /app/uploads

COPY ${LOCAL_RELAY_PATH:-nonexistent} /app/relay-server
RUN if [ -f /app/relay-server ]; then \
      chmod +x /app/relay-server; \
    else \
      if [ "$RELAY_VERSION" = "latest" ]; then \
        RELAY_VERSION=$(curl -s https://api.github.com/repos/RelayCore/relay-server/releases/latest | grep tag_name | cut -d '"' -f 4); \
      fi && \
      curl -L -o relay-server.tar.gz "https://github.com/RelayCore/relay-server/releases/download/${RELAY_VERSION}/relay-server_${RELAY_VERSION}_linux_amd64.zip" && \
      mkdir bin && \
      unzip relay-server.tar.gz -d bin && \
      mv bin/relay-server /app/relay-server && \
      rm -rf bin relay-server.tar.gz; \
    fi

EXPOSE 36954
CMD ["./relay-server"]