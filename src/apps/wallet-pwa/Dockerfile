# Wallet PWA Dockerfile
# Development/evaluation image; not a compliance or production claim

FROM node:22-alpine AS builder

WORKDIR /app

# pnpm version must match "packageManager" in package.json (checked by scripts/check-toolchain-pins.test.mjs)
RUN corepack enable && corepack prepare pnpm@10.34.9 --activate

# Copy root monorepo config
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json ./

# Copy required packages and the app
COPY src/packages ./src/packages
COPY src/apps/wallet-pwa ./src/apps/wallet-pwa

# Prune and Build
RUN pnpm install --frozen-lockfile
ARG VITE_WALLET_OPENER_ORIGINS=
ENV VITE_WALLET_OPENER_ORIGINS=$VITE_WALLET_OPENER_ORIGINS
RUN pnpm --filter "@askmi/wallet-pwa" build

# Production Image: Serve static files via Nginx for high performance/sovereignty
FROM nginx:alpine

# Copy built assets to nginx public folder
COPY --from=builder /app/src/apps/wallet-pwa/dist /usr/share/nginx/html

# Optional: Copy custom nginx config for SPA routing
# COPY src/apps/wallet-pwa/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
