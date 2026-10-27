BINARY := tcp-protocol-gateway
CMD    := ./cmd/gateway

.PHONY: build test race vet fmt clean linux-amd64 linux-arm64

build:
	go build -o $(BINARY) $(CMD)

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	go fmt ./...

clean:
	rm -f $(BINARY)

# 交叉编译 Linux 二进制（静态编译，可直接部署到无 Go 环境的服务器）
linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $(BINARY)-linux-amd64 $(CMD)

linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o $(BINARY)-linux-arm64 $(CMD)
