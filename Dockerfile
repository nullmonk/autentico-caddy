FROM caddy:builder-alpine AS builder

COPY . /src

RUN xcaddy build \
    --with github.com/nullmonk/autentico-caddy=/src

FROM caddy:alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
