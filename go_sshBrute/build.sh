rm -rf ssh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -v -x -trimpath -o ssh main.go
