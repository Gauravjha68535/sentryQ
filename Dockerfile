# Stage 1: Build the React frontend
FROM node:20-slim AS web-builder
WORKDIR /build/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 2: Build the Go binary (requires GCC for go-tree-sitter CGO)
FROM golang:1.26 AS go-builder
RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-builder /build/web/dist ./web/dist
RUN CGO_ENABLED=1 go build -trimpath -o /sentryq ./cmd/scanner

# Stage 3: Minimal runtime image
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates git && rm -rf /var/lib/apt/lists/*
COPY --from=go-builder /sentryq /usr/local/bin/sentryq
COPY --from=go-builder /build/rules /usr/local/share/sentryq/rules
EXPOSE 5336
ENV SENTRYQ_BIND=0.0.0.0
ENTRYPOINT ["/usr/local/bin/sentryq"]
