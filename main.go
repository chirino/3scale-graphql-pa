package main

import "github.com/chirino/3scale-graphql-pa/internal/cmd"

// GoReleaser sets these via ldflags:
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd.Main(cmd.VersionConfig{
		Version: version,
		Commit:  commit,
		Date:    date,
	})
}
