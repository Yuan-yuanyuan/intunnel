FROM twf39ytceccgn1b06u.xuanyuan.run/golang:1.22-alpine AS builder

WORKDIR /build

COPY go.mod .
RUN go env -w GOPROXY=https://goproxy.cn,direct && go mod download
COPY cmd/ ./cmd/
RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o tunnel     ./cmd/tunnel
RUN CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o tunnel.exe ./cmd/tunnel

FROM twf39ytceccgn1b06u.xuanyuan.run/alpine:latest
WORKDIR /output
COPY --from=builder /build/tunnel     .
COPY --from=builder /build/tunnel.exe .

CMD ["sh"]
