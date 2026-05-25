FROM node:22-alpine AS builder

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@9.15.9 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json tsconfig.json ./
COPY src/apps/verifier-demo/frontend ./src/apps/verifier-demo/frontend

ARG VITE_VERIFIER_BACKEND_URL=http://api.localhost/verifier
ARG VITE_WALLET_URL=http://wallet.localhost
ENV VITE_VERIFIER_BACKEND_URL=$VITE_VERIFIER_BACKEND_URL
ENV VITE_WALLET_URL=$VITE_WALLET_URL

RUN pnpm install --frozen-lockfile
RUN pnpm --filter verifier-frontend build

FROM caddy:2-alpine AS runner

COPY --from=builder /app/src/apps/verifier-demo/frontend/dist /usr/share/caddy

EXPOSE 8080

CMD ["caddy", "file-server", "--listen", ":8080", "--root", "/usr/share/caddy"]
