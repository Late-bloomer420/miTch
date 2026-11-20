# Verifier Backend Dockerfile
# Development/evaluation image; not a compliance or production claim

FROM node:22-alpine AS builder

WORKDIR /app

# pnpm version must match "packageManager" in package.json (checked by scripts/check-toolchain-pins.test.mjs)
RUN corepack enable && corepack prepare pnpm@10.34.9 --activate

# Copy root monorepo config
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json ./

# Copy required packages first (for turbo pruning/build)
COPY src/packages ./src/packages
COPY src/apps/verifier-demo/backend ./src/apps/verifier-demo/backend

# Prune and Build
RUN pnpm install --frozen-lockfile
RUN pnpm --filter verifier-backend build

# Production Image
FROM node:22-alpine

WORKDIR /app

COPY --from=builder /app/src/apps/verifier-demo/backend/dist ./dist
COPY --from=builder /app/src/apps/verifier-demo/backend/package.json ./
COPY --from=builder /app/node_modules ./node_modules

# Default Environment
ENV NODE_ENV=production
ENV PORT=3000
ENV ASKMI_TRUST_MODE=live

EXPOSE 3000

CMD ["node", "dist/index.js"]
