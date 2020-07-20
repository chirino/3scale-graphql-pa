package serve

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/chirino/3scale-graphql-pa/internal/cmd/root"
	"github.com/chirino/3scale-graphql-pa/internal/policyagent/proto"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/testdata"
)

var (
	tls      = false
	certFile = ""
	keyFile  = ""
	grpcPort = 10000

	Command = &cobra.Command{
		Use:   "serve",
		Short: "Runs the 3scale graphql-gw policy agent",
		Run: func(cmd *cobra.Command, args []string) {
			if err := run(); err != nil {
				log.Fatal(err)

			}
		},
		//PersistentPreRunE: config.PreRunLoad,
	}

)

func init() {
	Command.Flags().BoolVar(&tls, "tls", tls, "connection uses TLS if true, else plain TCP")
	Command.Flags().StringVar(&certFile, "cert-file", certFile, "the TLS cert file")
	Command.Flags().StringVar(&keyFile, "key-file", keyFile, "the TLS key file")
	Command.Flags().IntVar(&grpcPort, "port", grpcPort, "the TLS cert file")
	root.Command.AddCommand(Command)
}

func run() error {
	var opts []grpc.ServerOption
	if tls {
		if certFile == "" {
			certFile = testdata.Path("server1.pem")
		}
		if keyFile == "" {
			keyFile = testdata.Path("server1.key")
		}
		creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
		if err != nil {
			log.Fatalf("Failed to generate credentials %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", grpcPort))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer(opts...)
	proto.RegisterPolicyAgentServer(grpcServer, &server{})

	log.Println("3scale graphql-gw policy agent GRPC service available at:", lis.Addr())
	return grpcServer.Serve(lis)

}

////////////////////////////////////////////////////////////////////////////////////////
// server Implements the GRPC PolicyAgentServer service interface:
////////////////////////////////////////////////////////////////////////////////////////
type server struct {
}

func (s *server) Check(ctx context.Context, req *proto.CheckRequest) (*proto.CheckResponse, error) {
	resp := proto.CheckResponse{}
	for i, f := range req.Graphql.GetFields() {
		if (i % 2) == 1 {
			resp.Fields = append(resp.Fields, &proto.GraphQLFieldResponse{
				Path:  f.Path,
				Error: "You are not allowed to access odd fields",
			})
		}
	}
	return &resp, nil
}
