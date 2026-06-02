# Multi-stage Dockerfile for outlook-mcp-hardened.
#
# Build :
#   docker build -t outlook-mcp-hardened:0.3.0 -f deploy/Dockerfile .
#
# Run (HTTP-loopback for testing) :
#   docker run --rm -p 127.0.0.1:3000:3000 \
#     -e MS365_MCP_CLIENT_ID=... \
#     -e MS365_MCP_TENANT_ID=... \
#     -e OUTLOOK_MCP_PUBLIC_URL=http://localhost:3000 \
#     -e OUTLOOK_MCP_TRUSTED_PROXIES=127.0.0.1 \
#     -v outlook-mcp-state:/var/lib/outlook-mcp \
#     -v outlook-mcp-logs:/var/log/outlook-mcp \
#     outlook-mcp-hardened:0.3.0
#
# For HTTP-public deployment, put this container behind nginx/Caddy
# (config templates in deploy/nginx-outlook-mcp.conf and deploy/Caddyfile)
# and pass the reverse-proxy IP via OUTLOOK_MCP_TRUSTED_PROXIES.
#
# First-time auth : the device-code flow needs interactive `--login` once.
# Run a one-shot :
#   docker run --rm -it \
#     -e MS365_MCP_CLIENT_ID=... -e MS365_MCP_TENANT_ID=... \
#     -v outlook-mcp-state:/var/lib/outlook-mcp \
#     outlook-mcp-hardened:0.3.0 outlook-mcp-hardened --login
# Then the persistent volume retains the token cache for subsequent runs.

# ─────────────────────────────────────────────────────────────────────────
# Stage 1 — Build
# ─────────────────────────────────────────────────────────────────────────

FROM node:22-bookworm-slim AS build

WORKDIR /build

# Copy package files first for better layer caching
COPY package.json package-lock.json ./

# Install dependencies (deterministic via npm ci)
RUN npm ci --no-audit --no-fund

# Copy source + build
COPY . .
RUN npm run generate && npm run build

# Prune dev dependencies for the final stage
RUN npm prune --omit=dev

# ─────────────────────────────────────────────────────────────────────────
# Stage 2 — Runtime
# ─────────────────────────────────────────────────────────────────────────

FROM node:22-bookworm-slim AS runtime

# Install libsecret so keytar can use the OS keychain when available
# (graceful fallback to file storage otherwise — documented).
RUN apt-get update && \
    apt-get install -y --no-install-recommends libsecret-1-0 ca-certificates dumb-init && \
    rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd --system --uid 1001 --home /var/lib/outlook-mcp --shell /usr/sbin/nologin outlook-mcp && \
    install -d -o outlook-mcp -g outlook-mcp -m 0700 /var/lib/outlook-mcp && \
    install -d -o outlook-mcp -g outlook-mcp -m 0700 /var/log/outlook-mcp

WORKDIR /app

# Copy built artifacts and runtime dependencies
COPY --from=build --chown=root:root /build/dist /app/dist
COPY --from=build --chown=root:root /build/node_modules /app/node_modules
COPY --from=build --chown=root:root /build/package.json /app/package.json

# Defaults — override at `docker run -e ...` time
ENV NODE_ENV=production
ENV XDG_STATE_HOME=/var/lib/outlook-mcp
ENV OUTLOOK_MCP_LOGS_DIR=/var/log/outlook-mcp

USER outlook-mcp

# Document the listen port (this is informational ; the actual bind is
# decided by --http arg at runtime).
EXPOSE 3000

# Use dumb-init as PID 1 for proper signal forwarding to Node.
# Default cmd : HTTP loopback on 3000. Override via docker run command.
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "/app/dist/index.js", "--http", "0.0.0.0:3000"]

# ─────────────────────────────────────────────────────────────────────────
# OCI labels — useful for image registries + scanners
# ─────────────────────────────────────────────────────────────────────────

LABEL org.opencontainers.image.title="outlook-mcp-hardened"
LABEL org.opencontainers.image.description="Security-hardened MCP server for Microsoft Outlook (Mail + Calendar). Client-agnostic, audit-trail + egress allowlist + OAuth proxy hardening."
LABEL org.opencontainers.image.url="https://github.com/Ixtria/outlook-mcp-hardened"
LABEL org.opencontainers.image.source="https://github.com/Ixtria/outlook-mcp-hardened"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="Ixtria SA"
