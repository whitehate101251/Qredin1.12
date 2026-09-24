package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/qredin/qredin/internal/config"
)

var (
	configPath = flag.String("config", "", "Path to configuration file")
	version    = flag.Bool("version", false, "Print version and exit")
)

func main() {
	flag.Parse()

	if *version {
		printVersion()
		os.Exit(0)
	}

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "config path is required; use --config")
		os.Exit(1)
	}

	if err := config.ValidatePath(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "invalid config path: %v\n", err)
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	out := map[string]interface{}{
		"status": "valid",
		"config": cfg,
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write output: %v\n", err)
		os.Exit(1)
	}
}

func printVersion() {
	enc, _ := json.MarshalIndent(map[string]string{"version": "dev"}, "", "  ")
	fmt.Println(string(enc))
}