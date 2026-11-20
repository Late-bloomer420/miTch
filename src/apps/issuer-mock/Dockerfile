# Mock Issuer Dockerfile
# Development/evaluation image; not a compliance or production claim

FROM node:22-alpine AS builder

WORKDIR /app

# pnpm version must match "packageManager" in package.json (checked by scripts/check-toolchain-pins.test.mjs)
RUN corepack enable && corepack prepare pnpm@10.34.9 --activate

# Copy root monorepo config
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json ./

# Copy required packages and the app
COPY src/packages ./src/packages
COPY src/apps/issuer-mock ./src/apps/issuer-mock

# Prune and Build
RUN pnpm install --frozen-lockfile
RUN pnpm --filter "@askmi/issuer-mock" build

# Production Image
FROM node:22-alpine

WORKDIR /app

COPY --from=builder /app/src/apps/issuer-mock/dist ./dist
COPY --from=builder /app/src/apps/issuer-mock/package.json ./
COPY --from=builder /app/node_modules ./node_modules

# Default Environment
ENV NODE_ENV=production
ENV PORT=4000

EXPOSE 4000

CMD ["node", "dist/index.js"]
