# Mock Issuer Dockerfile
# Based on miTch 100% Compliance Architecture

FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies (pnpm is used in monorepo)
RUN npm install -g pnpm

# Copy root monorepo config
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json ./

# Copy required packages and the app
COPY src/packages ./src/packages
COPY src/apps/issuer-mock ./src/apps/issuer-mock

# Prune and Build
RUN pnpm install --frozen-lockfile
RUN pnpm --filter "@mitch/issuer-mock" build

# Production Image
FROM node:20-alpine

WORKDIR /app

COPY --from=builder /app/src/apps/issuer-mock/dist ./dist
COPY --from=builder /app/src/apps/issuer-mock/package.json ./
COPY --from=builder /app/node_modules ./node_modules

# Default Environment
ENV NODE_ENV=production
ENV PORT=4000

EXPOSE 4000

CMD ["node", "dist/index.js"]
