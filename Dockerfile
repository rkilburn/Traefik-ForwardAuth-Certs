FROM golang:1.15-alpine as builder

# Build
COPY . /build
WORKDIR /build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o traefik-forwardauth-certificates

# Create deployment image
FROM scratch
COPY --from=builder /build/traefik-forwardauth-certificates ./
EXPOSE 8443
ENTRYPOINT ["./traefik-forwardauth-certificates"]