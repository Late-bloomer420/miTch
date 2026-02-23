# Build Stage
FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json turbo.json pnpm-lock.yaml pnpm-workspace.yaml ./

# Install pnpm
RUN npm install -g pnpm

# Copy source code
COPY apps/verifier-demo/backend ./apps/verifier-demo/backend
COPY packages ./packages

# Install dependencies
RUN pnpm install --frozen-lockfile

# Build the backend (and dependencies)
RUN pnpm filter "verifier-backend..." build

# Runtime Stage
FROM node:20-alpine AS runner

WORKDIR /app

RUN npm install -g pnpm

# Copy built artifacts and necessary files
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages ./packages
COPY --from=builder /app/apps/verifier-demo/backend ./apps/verifier-demo/backend

WORKDIR /app/apps/verifier-demo/backend

# Expose port
EXPOSE 3002

# Start the application
CMD ["pnpm", "start"]
