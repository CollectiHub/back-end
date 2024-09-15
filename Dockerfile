# The build stage
FROM golang:1.23.1 AS builder
WORKDIR /app
COPY . .
COPY .env.docker /app/.env
RUN go build -o api-build /app/cmd/api

# The run stage
FROM debian:stable-slim

WORKDIR /app

COPY --from=builder /app/api-build .
COPY --from=builder /app/.env .

CMD ["./api-build"]
