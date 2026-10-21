FROM cgr.dev/chainguard/go:latest AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/privatebin-go ./cmd/privatebin-go

FROM cgr.dev/chainguard/static:latest
COPY --from=build /out/privatebin-go /privatebin-go
EXPOSE 8080 9090
ENTRYPOINT ["/privatebin-go"]
