# Relay Server

Relay Server is a real-time communication server designed for group chat, file sharing, and voice communication. For the client see [relay-client](https://github.com/RelayCore/relay-client).

## Getting Started

### Prerequisites

-   [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/)
-   (Optional) SSL certificates for HTTPS (self-signed or from a CA)

### Quick Start

1. **Clone the repository:**

    ```sh
    git clone https://github.com/RelayCore/relay-server.git
    cd relay-server
    ```

2. **Configure the server:**

    - Edit `config.yaml` to customize server name, description, port, and other settings.
    - Place SSL certificates in the `certs/` directory as `cert.pem` and `key.pem` for HTTPS support.

3. **Start the server:**

    ```sh
    docker-compose up --build
    ```

4. **Access the server:**
    - By default, the server runs on port `36954`.
    - Visit `http://localhost:36954` or `https://localhost:36954` in your browser.

## Docker Compose Profiles

Relay Server uses Docker Compose profiles to select how the server is run and which Nginx configuration is used:

-   **local**: Runs the server without SSL, using a local Nginx configuration.
    Start with:

    ```sh
    docker-compose --profile local up --build
    ```

-   **letsencrypt**: Enables Let's Encrypt SSL certificates for HTTPS.
    Requires the `DOMAIN` environment variable to be set.
    Start with:

    ```sh
    DOMAIN=your.domain.com docker-compose --profile letsencrypt up --build
    ```

-   **selfsigned**: Uses self-signed SSL certificates for HTTPS.
    Place your self-signed certificates in the `nginx/selfsigned` directory.
    Start with:
    ```sh
    docker-compose --profile selfsigned up --build
    ```

If no profile is specified, the default is to run without SSL.

## Configuration

The server is configured via `config.yaml`. Example options:

```yaml
name: "Relay Server"
description: "A real-time communication server"
allow_invite: true
max_users: 100
max_file_size: 52428800
max_attachments: 10
icon: ""
port: ":36954"
tenor_api_key: ""
domain: ""
```

## API

The server exposes a REST API and WebSocket endpoint. See the code for available endpoints and their usage.

## Development

To build and run locally without Docker:

```sh
go build -o relay-server ./cmd/server
./relay-server
```

## License

This project is licensed under the MIT License.
