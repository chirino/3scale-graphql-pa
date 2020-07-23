FROM golang:alpine as build
RUN apk --no-cache add ca-certificates

# In case we want to build the in docker....
#WORKDIR /go/src/app
#COPY . .
#RUN CGO_ENABLED=0 go-wrapper install -ldflags '-extldflags "-static"'

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ADD bin /bin
EXPOSE 10000/tcp
ENTRYPOINT ["/bin/3scale-graphql-pa"]