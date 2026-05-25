# Verifier Backend Dockerfile
# Based on miTch 100% Compliance Architecture

FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies (pnpm is used in monorepo)
RUN npm install -g pnpm

# Copy root monorepo config
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json ./

# Copy required packages first (for turbo pruning/build)
COPY src/packages ./src/packages
COPY src/apps/verifier-demo/backend ./src/apps/verifier-demo/backend

# Prune and Build
RUN pnpm install --frozen-lockfile
RUN pnpm --filter verifier-backend build

# Production Image
FROM node:20-alpine

WORKDIR /app

COPY --from=builder /app/src/apps/verifier-demo/backend/dist ./dist
COPY --from=builder /app/src/apps/verifier-demo/backend/package.json ./
COPY --from=builder /app/node_modules ./node_modules

# Default Environment
ENV NODE_ENV=production
ENV PORT=3000
ENV MITCH_TRUST_MODE=live

EXPOSE 3000

CMD ["node", "dist/index.js"]
