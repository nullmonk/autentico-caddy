FROM golang:alpine AS builder

WORKDIR /src
COPY . .

RUN go build -o /usr/bin/caddy cmd/main.go

FROM caddy:alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
