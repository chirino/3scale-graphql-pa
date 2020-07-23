module github.com/chirino/3scale-graphql-pa

require (
	github.com/3scale/3scale-authorizer v0.0.1
	github.com/3scale/3scale-go-client v0.4.1-0.20200527144043-59f1bbdf5147
	github.com/3scale/3scale-porta-go-client v0.0.5
	github.com/chirino/hawtgo v0.0.1
	github.com/golang/protobuf v1.3.1
	github.com/kr/text v0.2.0 // indirect
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.4.0
	github.com/stretchr/testify v1.5.1 // indirect
	golang.org/x/net v0.0.0-20190620200207-3b0461eec859 // indirect
	golang.org/x/sys v0.0.0-20200620081246-981b61492c35 // indirect
	google.golang.org/grpc v1.21.0
	gopkg.in/yaml.v2 v2.3.0 // indirect
)

go 1.13

// replace github.com/3scale/3scale-porta-go-client => ../3scale-porta-go-client
// replace github.com/3scale/3scale-authorizer => ../3scale-authorizer
