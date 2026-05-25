FROM node:22-alpine AS builder

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@9.15.9 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json tsconfig.json ./
COPY src/packages ./src/packages
COPY src/apps/issuer-mock ./src/apps/issuer-mock

RUN pnpm install --frozen-lockfile
RUN pnpm --filter @mitch/issuer-mock... build

FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3005

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/src/packages ./src/packages
COPY --from=builder /app/src/apps/issuer-mock ./src/apps/issuer-mock

WORKDIR /app/src/apps/issuer-mock

EXPOSE 3005

CMD ["node", "dist/index.js"]
