#!/usr/bin/env bash
set -e
cd -P $(dirname "${BASH_SOURCE[0]}")

mkdir -p bin || true 2> /dev/null
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./bin/3scale-graphql-pa ../main.go

docker build -t "chirino/3scale-graphql-pa" .
# docker push chirino/3scale-graphql-pa
