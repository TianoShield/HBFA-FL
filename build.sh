#!/usr/bin/env bash
set -euo pipefail

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Get host UID/GID dynamically
HOST_UID=$(id -u)
HOST_GID=$(id -g)

# Parse arguments
NO_CACHE=""
if [[ "${1:-}" == "--no-cache" ]]; then
    NO_CACHE="--no-cache"
    echo "Building with --no-cache"
fi

echo "============================================"
echo "Building HBFA-FL Docker Image"
echo "============================================"
echo "UID:GID = ${HOST_UID}:${HOST_GID}"
echo ""

# Build the Docker image using Docker Compose from .devcontainer
HOST_UID=${HOST_UID} HOST_GID=${HOST_GID} docker compose -f "${SCRIPT_DIR}/.devcontainer/docker-compose.yml" build ${NO_CACHE}

echo ""
echo "============================================"
echo "Image built successfully!"
echo "============================================"
echo ""
echo "Next steps:"
echo "  docker compose -f .devcontainer/docker-compose.yml up -d"
echo "  docker exec -it hbfa-fl-container bash"
echo "  OR: VS Code - Reopen in Container (Dev Container Extension)"
echo ""
