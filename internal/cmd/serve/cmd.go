package serve

import (
	"context"
	"crypto/tls"
	"errors"
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
	tlsFlag               func() bool
	certFile              func() string
	keyFile               func() string
	grpcPort              func() int
	threeScaleAccessToken func() string
	threeScaleSystemURL   func() string
	threeScaleServiceId   func() string
	threeScaleEnv         func() string
	threeScaleInsecure    func() bool

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
	tlsFlag = root.BoolBind(Command.Flags(), "tls", false, "connection uses TLS if true, else plain TCP")
	certFile = root.StringBind(Command.Flags(), "cert-file", "", "the TLS cert file")
	keyFile = root.StringBind(Command.Flags(), "key-file", "", "the TLS key file")
	grpcPort = root.IntBind(Command.Flags(), "port", 10000, "use Viper for configuration")
	threeScaleAccessToken = root.StringBind(Command.Flags(), "3scale-access-token", "", "the 3scale access token")
	threeScaleSystemURL = root.StringBind(Command.Flags(), "3scale-url", "", "the 3scale system url")
	threeScaleServiceId = root.StringBind(Command.Flags(), "3scale-service-id", "", "the 3scale service id")
	threeScaleEnv = root.StringBind(Command.Flags(), "3scale-env", "production", "the 3scale environment.  One of (staging | production)")
	threeScaleInsecure = root.BoolBind(Command.Flags(), "3scale-insecure", false, "allow insecure TLS connections to the 3scale service")
	root.Command.AddCommand(Command)
}

func run() error {

	var opts []grpc.ServerOption
	if tlsFlag() {
		certFile := certFile()
		if certFile == "" {
			certFile = testdata.Path("server1.pem")
		}
		keyFile := keyFile()
		if keyFile == "" {
			keyFile = testdata.Path("server1.key")
		}
		creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
		if err != nil {
			log.Fatalf("Failed to generate credentials %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", grpcPort()))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	hc := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: threeScaleInsecure()},
	}}
	cache := authorizer.NewSystemCache(authorizer.SystemCacheConfig{}, nil)
	manager := authorizer.NewManager(hc, cache, authorizer.BackendConfig{}, &authorizer.MetricsReporter{})

	grpcServer := grpc.NewServer(opts...)

	// manager gets the system configuration (and caches it)
	systemConf, err := manager.GetSystemConfiguration(threeScaleSystemURL(), authorizer.SystemRequest{
		AccessToken: threeScaleAccessToken(),
		ServiceID:   threeScaleServiceId(),
		Environment: threeScaleEnv(),
	})
	if err != nil {
		return err
	}
	metricsBuilder, err := getMetricsBuilder(systemConf)
	if err != nil {
		return err
	}

	proto.RegisterPolicyAgentServer(grpcServer, &server{
		manager:        manager,
		proxyConf:      systemConf,
		metricsBuilder: metricsBuilder,
	})

	log.Println("3scale graphql-gw policy agent GRPC service available at:", lis.Addr())
	return grpcServer.Serve(lis)

}

////////////////////////////////////////////////////////////////////////////////////////
// server Implements the GRPC PolicyAgentServer service interface:
////////////////////////////////////////////////////////////////////////////////////////
type server struct {
	manager        *authorizer.Manager
	proxyConf      system.ProxyConfig
	metricsBuilder func(path string, method string) api.Metrics
}

func getProtoHeader(headers []*proto.Header, name string) string {
	for _, header := range headers {
		if header.Name == name {
			return header.Value
		}
	}
	return ""
}

func (s *server) Check(ctx context.Context, req *proto.CheckRequest) (*proto.CheckResponse, error) {

	// Would be better if the manager was caching the metricsBuilder, to avoid the extra work
	// of regex parsing and be able to free up more memory.  metricsBuilder only needs a subset of
	// the data in the systemConf
	params, err := getAuthParams(s.proxyConf, req)
	if err != nil {
		return nil, err
	}

	log.Printf("checking %d graphql fields", len(req.Graphql.GetFields()))
	resp := proto.CheckResponse{}
	for _, f := range req.Graphql.GetFields() {
		metrics := s.metricsBuilder(f.Path, "GET")
		if len(metrics) > 0 {
			log.Printf("issuing authrep for: %s", f.Path)
			authRep, err := s.manager.AuthRep(threeScaleSystemURL(), authorizer.BackendRequest{
				Auth: authorizer.BackendAuth{
					Type:  s.proxyConf.Content.BackendAuthenticationType,
					Value: s.proxyConf.Content.BackendAuthenticationValue,
				},
				Service: threeScaleServiceId(),
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
	}
	log.Printf("checks done, failed: %d", len(resp.Fields))
	return &resp, nil
}

func getAuthParams(proxyConfig system.ProxyConfig, req *proto.CheckRequest) (authorizer.BackendParams, error) {

	return authorizer.BackendParams{
		AppID:   getProtoHeader(req.Http.Headers, "X-3Scale-AppID"),
		AppKey:  getProtoHeader(req.Http.Headers, "X-3Scale-AppKey"),
		UserKey: getProtoHeader(req.Http.Headers, "X-3Scale-UserKey"),
	}, nil

	// In case we want to do it more like APICast extracts them... but for now just assume
	// that APICast will extract these for us and set them as headers that can be reused.
	proxyConf := proxyConfig.Content.Proxy
	if proxyConf.AuthAppID == `` {
		proxyConf.AuthAppID = `app_id`
	}
	if proxyConf.AuthAppKey == `` {
		proxyConf.AuthAppKey = `app_key`
	}
	if proxyConf.AuthUserKey == `` {
		proxyConf.AuthUserKey = `user_key`
	}

	userKey := ""
	appId := ""
	appKey := ""

	switch proxyConfig.Content.BackendVersion {
	case "1":
		switch proxyConf.CredentialsLocation {
		case `query`:
			// TODO:
			return authorizer.BackendParams{}, errors.New(`query credentials location not supported yet`)
		case `headers`:
			userKey = getProtoHeader(req.Http.Headers, proxyConf.AuthUserKey)
		case `authorization`:

			authorizationHeader := getProtoHeader(req.Http.Headers, `Authorization`)
			if strings.HasPrefix(authorizationHeader, "Basic ") {
				x := http.Request{}
				x.Header.Add("Authorization", authorizationHeader)
				if username, password, ok := x.BasicAuth(); ok {
					if username != "" {
						userKey = username
					} else {
						userKey = password
					}
				}
			} else if strings.HasPrefix(authorizationHeader, "Bearer ") {
				userKey = strings.TrimPrefix(authorizationHeader, "Bearer ")
			}
		default:
			return authorizer.BackendParams{}, errors.New(`invalid credentials location`)
		}

	case "2":

		switch proxyConf.CredentialsLocation {
		case `query`:
			// TODO:
			return authorizer.BackendParams{}, errors.New(`query credentials location not supported yet`)
		case `headers`:

			appIdHeader := ""
			appKeyHeader := ""
			for _, header := range req.Http.Headers {
				switch header.Name {
				case proxyConf.AuthAppID:
					appIdHeader = header.Value
				case proxyConf.AuthAppKey:
					appKeyHeader = header.Value
				}
			}
			appId = appIdHeader
			appKey = appKeyHeader

		case `authorization`:
			authorizationHeader := getProtoHeader(req.Http.Headers, `Authorization`)
			if strings.HasPrefix(authorizationHeader, "Basic ") {
				x := http.Request{}
				x.Header.Add("Authorization", authorizationHeader)
				if username, password, ok := x.BasicAuth(); ok {
					appId = username
					userKey = password
				}
			} else if strings.HasPrefix(authorizationHeader, "Bearer ") {
				appId = strings.TrimPrefix(authorizationHeader, "Bearer ")
			}
		default:
			return authorizer.BackendParams{}, errors.New(`invalid credentials location`)
		}

	default:
		return authorizer.BackendParams{}, fmt.Errorf(`%s backend version not yet supported`, proxyConfig.Content.BackendVersion)
	}
	return authorizer.BackendParams{
		AppID:   appId,
		AppKey:  appKey,
		UserKey: userKey,
	}, nil
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
		log.Println("compiling rule pattern: ", pr.Pattern)
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
