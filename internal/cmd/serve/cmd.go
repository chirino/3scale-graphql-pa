package serve

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/3scale/3scale-authorizer/pkg/authorizer"
	"github.com/3scale/3scale-go-client/threescale/api"
	system "github.com/3scale/3scale-porta-go-client/client"
	"github.com/chirino/3scale-graphql-pa/internal/cmd/root"
	"github.com/chirino/3scale-graphql-pa/internal/policyagent/proto"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/testdata"
)

var (
	tlsFlag               = false
	certFile              = ""
	keyFile               = ""
	grpcPort              = 10000
	threeScaleAccessToken = ""
	threeScaleSystemURL   = ""
	threeScaleServiceId   = ""
	threeScaleEnv         = "production"
	threeScaleInsecure    = false

	Command = &cobra.Command{
		Use:   "serve",
		Short: "Runs the 3scale graphql-gw policy agent",
		Run: func(cmd *cobra.Command, args []string) {
			if err := run(); err != nil {
				log.Fatal(err)

			}
		},
	}
)

func init() {
	Command.Flags().IntVar(&grpcPort, "port", grpcPort, "the grcp port the server will listen on")
	Command.Flags().BoolVar(&tlsFlag, "tls", tlsFlag, "connection uses TLS if true, else plain TCP")
	Command.Flags().StringVar(&certFile, "cert-file", certFile, "the TLS cert file")
	Command.Flags().StringVar(&keyFile, "key-file", keyFile, "the TLS key file")
	Command.Flags().StringVar(&threeScaleSystemURL, "3scale-url", threeScaleSystemURL, "the 3scale system url")
	Command.Flags().StringVar(&threeScaleAccessToken, "3scale-access-token", threeScaleAccessToken, "the 3scale access token")
	Command.Flags().StringVar(&threeScaleServiceId, "3scale-service-id", threeScaleServiceId, "the 3scale service id")
	Command.Flags().StringVar(&threeScaleEnv, "3scale-env", threeScaleEnv, "the 3scale environment.  One of (staging | production)")
	Command.Flags().BoolVar(&threeScaleInsecure, "3scale-insecure", threeScaleInsecure, "allow insecure TLS connections to the 3scale service")
	root.Command.AddCommand(Command)
}

func run() error {
	var opts []grpc.ServerOption
	if tlsFlag {
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

	hc := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: threeScaleInsecure},
	}}
	cache := authorizer.NewSystemCache(authorizer.SystemCacheConfig{}, nil)
	manager := authorizer.NewManager(hc, cache, authorizer.BackendConfig{}, &authorizer.MetricsReporter{})

	grpcServer := grpc.NewServer(opts...)
	proto.RegisterPolicyAgentServer(grpcServer, &server{
		manager: manager,
	})

	log.Println("3scale graphql-gw policy agent GRPC service available at:", lis.Addr())
	return grpcServer.Serve(lis)

}

////////////////////////////////////////////////////////////////////////////////////////
// server Implements the GRPC PolicyAgentServer service interface:
////////////////////////////////////////////////////////////////////////////////////////
type server struct {
	manager *authorizer.Manager
}

func (s *server) Check(ctx context.Context, req *proto.CheckRequest) (*proto.CheckResponse, error) {

	// manager gets the system configuration (and caches it)
	systemConf, err := s.manager.GetSystemConfiguration(threeScaleSystemURL, authorizer.SystemRequest{
		AccessToken: threeScaleAccessToken,
		ServiceID:   threeScaleServiceId,
		Environment: threeScaleEnv,
	})
	if err != nil {
		return nil, err
	}
	metricsBuilder, err := getMetricsBuilder(systemConf)
	if err != nil {
		return nil, err
	}
	// Would be better if the manager was caching the metricsBuilder, to avoid the extra work
	// of regex parsing and be able to free up more memory.  metricsBuilder only needs a subset of
	// the data in the systemConf

	//appIdentifierKey := "app_id"
	//if systemConf.Content.BackendVersion == "oauth" {
	//	// OIDC integration configured so force app identifier to come from jwt claims
	//	appIdentifierKey = "client_id"
	//}
	params := authorizer.BackendParams{
		// TODO:
		//AppID:   appID,
		//AppKey:  appKey,
		//UserKey: userKey,
	}

	resp := proto.CheckResponse{}
	for _, f := range req.Graphql.GetFields() {
		metrics := metricsBuilder(f.Path, "GET")
		authRep, err := s.manager.AuthRep(threeScaleSystemURL, authorizer.BackendRequest{
			Auth: authorizer.BackendAuth{
				Type:  systemConf.Content.BackendAuthenticationType,
				Value: systemConf.Content.BackendAuthenticationValue,
			},
			Service: threeScaleServiceId,
			Transactions: []authorizer.BackendTransaction{
				{
					Metrics: metrics,
					Params:  params,
				},
			},
		})
		if err != nil {
			resp.Fields = append(resp.Fields, &proto.GraphQLFieldResponse{
				Path:  f.Path,
				Error: err.Error(),
			})
		} else {
			if !authRep.Authorized {
				resp.Fields = append(resp.Fields, &proto.GraphQLFieldResponse{
					Path:  f.Path,
					Error: "Not Authorized: " + authRep.RejectedReason,
				})
			}
		}
	}
	return &resp, nil
}

func getMetricsBuilder(conf system.ProxyConfig) (func(path string, method string) api.Metrics, error) {

	// sort proxy rules based on Position field to establish priority
	sort.Slice(conf.Content.Proxy.ProxyRules, func(i, j int) bool {
		return conf.Content.Proxy.ProxyRules[i].Position < conf.Content.Proxy.ProxyRules[j].Position
	})

	type r struct {
		re               *regexp.Regexp
		method           string
		MetricSystemName string
		Delta            int
	}

	rules := make([]r, len(conf.Content.Proxy.ProxyRules))
	for i, pr := range conf.Content.Proxy.ProxyRules {
		re, err := regexp.Compile(pr.Pattern)
		if err != nil {
			return nil, err
		}
		rules[i] = r{
			re:               re,
			method:           strings.ToUpper(pr.HTTPMethod),
			MetricSystemName: pr.MetricSystemName,
			Delta:            int(pr.Delta),
		}
	}

	return func(path string, method string) api.Metrics {
		metrics := make(api.Metrics)
		for _, r := range rules {
			if r.method == method && r.re.MatchString(path) {
				metrics.Add(r.MetricSystemName, int(r.Delta))
			}
		}
		return metrics
	}, nil
}
