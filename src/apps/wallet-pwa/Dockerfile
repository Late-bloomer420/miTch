FROM node:22-alpine AS builder

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@9.15.9 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json tsconfig.json ./
COPY src/packages ./src/packages
COPY src/apps/wallet-pwa ./src/apps/wallet-pwa

ARG VITE_VERIFIER_URL=http://api.localhost/verifier/present
ARG VITE_ISSUER_URL=http://api.localhost/issuer/credential
ARG VITE_ISSUER_DID=did:web:issuer.localhost
ENV VITE_VERIFIER_URL=$VITE_VERIFIER_URL
ENV VITE_ISSUER_URL=$VITE_ISSUER_URL
ENV VITE_ISSUER_DID=$VITE_ISSUER_DID

RUN pnpm install --frozen-lockfile
RUN pnpm --filter @mitch/wallet-pwa... build

FROM caddy:2-alpine AS runner

COPY --from=builder /app/src/apps/wallet-pwa/dist /usr/share/caddy

EXPOSE 8080

CMD ["caddy", "file-server", "--listen", ":8080", "--root", "/usr/share/caddy"]
