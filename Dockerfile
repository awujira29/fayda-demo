# Single-service image: build the React SPA, then serve API + static files
# from one FastAPI process. Multi-stage so the runtime image carries no Node.

# ---- stage 1: frontend build -------------------------------------------------
FROM node:22-alpine AS ui
# Toolchain for native transitive deps (utf-8-validate via the connector's
# websocket stack) — build stage only, never in the runtime image.
RUN apk add --no-cache python3 make g++
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# The Privy app id is runtime config (served by the backend at /config.js),
# so this build needs no secrets and never has to be repeated to rotate it.
RUN npm run build

# ---- stage 2: runtime --------------------------------------------------------
FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend/ backend/
COPY --from=ui /ui/dist frontend/dist

WORKDIR /app/backend
# Render sets PORT (default 10000). app.py derives its self-call base URL from
# the same variable, so the OIDC token/userinfo self-requests always match.
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-10000}"]
