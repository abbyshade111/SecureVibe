# Runs this app in a container, so it can be moved to another computer or a server without installing anything
# but Docker. Nothing about the app changes: the image is the same code, the same settings file and the same data
# folder it uses on your own machine.
#
# Two things are deliberately kept out of the image: your secrets and your data. The `.env` file and the `data`
# folder are excluded by `.dockerignore` and handed to the container when it starts (see compose.yaml), so an image
# you copy, publish or share can never carry your keys or anybody's records inside it.

# --- Stage 1: work out which packages the app needs to run -------------------------------------------------------
FROM node:26-alpine AS deps
WORKDIR /app
# Only the two package files, so this step is repeated only when the dependencies really change.
COPY package.json package-lock.json ./
# --omit=dev leaves out everything that is only needed for testing; --ignore-scripts means no package can run code
# of its own while being installed, which is the same rule SecureVibe applies when it builds the app.
RUN npm ci --omit=dev --ignore-scripts

# --- Stage 2: the image that actually runs -----------------------------------------------------------------------
FROM node:26-alpine AS runtime

# Production mode: no debug output, no development-only behaviour.
ENV NODE_ENV=production
# Inside a container "this computer" is the container itself, so the app listens on every address in here. It is
# still reachable only from where the port is published to, and compose.yaml publishes it to this computer alone.
ENV BIND_LAN=1
ENV PORT=3000
ENV DATA_DIR=/app/data

WORKDIR /app

# The node image already has an unprivileged user called "node"; the app never runs as root.
COPY --chown=node:node --from=deps /app/node_modules ./node_modules
COPY --chown=node:node . .

# The database, uploads and logs live here. It is the only place the app writes, and compose.yaml keeps it outside
# the container so your records survive rebuilding the image.
RUN mkdir -p /app/data && chown -R node:node /app/data
VOLUME ["/app/data"]

USER node
EXPOSE 3000

# Docker asks the app's own health endpoint whether it is ready; it answers without touching the database.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 3000) + '/healthz').then((r) => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

# `npm start` runs the same pre-flight check as on your own computer: it refuses to start if a secret is missing or
# still has its example value, and says which one in plain language.
CMD ["npm", "start"]
