# Standard Dockerfile for go-ios
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binaries
RUN go build -ldflags="-s -w" -o go-ios .
RUN go build -ldflags="-s -w" -o ostrace ./cmd/ostrace

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates libusb usbmuxd

# Create non-root user
RUN addgroup -g 1000 goios && \
    adduser -u 1000 -G goios -D goios

# Copy binaries from builder
COPY --from=builder /build/go-ios /usr/local/bin/
COPY --from=builder /build/ostrace /usr/local/bin/

# Set permissions
RUN chmod +x /usr/local/bin/go-ios /usr/local/bin/ostrace

# Switch to non-root user
USER goios

# Set entrypoint
ENTRYPOINT ["go-ios"]
