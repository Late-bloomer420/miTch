# Build Stage
FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json turbo.json pnpm-lock.yaml pnpm-workspace.yaml ./

# Install pnpm
RUN npm install -g pnpm

# Copy source code
COPY apps/wallet-pwa ./apps/wallet-pwa
COPY packages ./packages

# Install dependencies (frozen-lockfile for consistency)
RUN pnpm install --frozen-lockfile

# Build the app
RUN pnpm filter "@mitch/wallet-pwa" build

# Serve Stage
FROM node:20-alpine AS runner

WORKDIR /app

RUN npm install -g serve

# Copy built assets from builder
COPY --from=builder /app/apps/wallet-pwa/dist ./dist

# Expose port (default Vite/Serve)
EXPOSE 5173

# Start static file server
CMD ["serve", "-s", "dist", "-l", "5173"]
