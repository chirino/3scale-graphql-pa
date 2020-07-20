# 3scale-graphql-pa is a policy agent for the [graphql-gw](https://github.com/chirino/graphql-gw)

This project implements a graphql policy agent GRPC server using
the 3scale API management platform to manage your GraphQL endpoints.

### Installing Prebuilt Binaries

Please download [latest github release](https://github.com/chirino/3scale-graphql-pa/releases) for your platform

### Installing from Source

If you have a recent [go](https://golang.org/dl/) SDK installed:

`go get -u github.com/chirino/3scale-graphql-pa`

## Getting started

Run the server using this command:

```bash
$ 3scale-graphql-pa serve
```
 
## Build from source

```bash
go build -o=3scale-graphql-pa main.go
```

## License

[BSD](./LICENSE)

## Development

- We love [pull requests](https://github.com/chirino/3scale-graphql-pa/pulls)
- [Open Issues](https://github.com/chirino/3scale-graphql-pa/issues)
- 3scale-graphql-pa is written in [Go](https://golang.org/). It should work on any platform where go is supported.
