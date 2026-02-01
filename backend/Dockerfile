# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev libpcap-dev sqlite-dev

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY backend/ ./backend/

# Build the application
RUN CGO_ENABLED=1 CGO_CFLAGS="-D_LARGEFILE64_SOURCE" GOOS=linux go build -tags "sqlite_omit_load_extension" -o server ./backend/cmd/server


# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache libpcap ca-certificates sqlite-libs

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/server .

# Create necessary directories
RUN mkdir -p /app/backend/uploads /app/backend/data

# Expose port
EXPOSE 8080

# Run the application
CMD ["./server"]
