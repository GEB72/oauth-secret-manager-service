# Build stage
FROM golang:1.23.2 as builder

# Set the working directory in the container to /app
WORKDIR /app

# Copy go.mod and go.sum first to cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire project into the container
COPY . .

# Set the working directory to where main.go is located
WORKDIR /app/cmd/main

# Build the Go application with static linking for compatibility
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /app/oauth-secret-manager-service

# Final stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates

# Set the working directory for the final container
WORKDIR /root/

# Copy the compiled binary from the builder stage
COPY --from=builder /app/oauth-secret-manager-service .

# Ensure the binary has executable permissions
RUN chmod +x /root/oauth-secret-manager-service

# Command to run the binary
ENTRYPOINT ["./oauth-secret-manager-service"]

