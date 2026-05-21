FROM node:20-alpine

WORKDIR /app

# Install dependencies first so this layer is cached independently of app code.
# package-lock.json* — the glob makes the lock file optional so a fresh clone
# without a lock file still builds successfully.
COPY package.json package-lock.json* ./
RUN npm install

# Copy application source (overridden at runtime by a volume mount in Docker
# Compose, but present for standalone image builds and CI).
COPY . .

EXPOSE 3000

# Default: Next.js development server with hot reload.
CMD ["npm", "run", "dev"]
