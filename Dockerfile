FROM golang:alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY *.go ./
RUN go build -o /usr/bin/caddy cmd/main.go

FROM caddy:alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
