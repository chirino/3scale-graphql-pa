package cmd

import (
	_ "github.com/chirino/3scale-graphql-pa/internal/cmd/completion"
	"github.com/chirino/3scale-graphql-pa/internal/cmd/root"
	_ "github.com/chirino/3scale-graphql-pa/internal/cmd/serve"
	"github.com/chirino/3scale-graphql-pa/internal/cmd/version"
)

type VersionConfig = version.VersionConfig

func Main(versionConfig VersionConfig) {
	version.Config = versionConfig
	root.Main()
}
