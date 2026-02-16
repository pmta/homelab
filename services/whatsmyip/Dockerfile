# Build a small static Go binary and copy to scratch
FROM golang:1.20-alpine AS build
RUN apk add --no-cache git ca-certificates
WORKDIR /src
# Use module-aware build with cache hints
COPY . .
RUN go mod download || true
# Build a static binary suitable for scratch: disable cgo and strip symbol table
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN go build -ldflags='-s -w' -o /out/whatsmyip ./cmd/whatsmyip

FROM scratch
# copy certs (not strictly necessary for simple service) -- keep container minimal
COPY --from=build /out/whatsmyip /whatsmyip
COPY web /web
EXPOSE 8080
ENTRYPOINT ["/whatsmyip"]

# container healthcheck: run the binary in healthcheck mode
HEALTHCHECK --interval=30s --timeout=3s CMD ["/whatsmyip", "--healthcheck"]
