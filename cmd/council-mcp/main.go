package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yoannchl/the-council/internal/mcpserver"
	"github.com/yoannchl/the-council/internal/store"
)

func main() {
	// All logs must go to stderr per MCP protocol requirements.
	log.SetOutput(os.Stderr)
	log.SetFlags(log.Ltime | log.Lshortfile)

	dbPath := flag.String("db", "", "Path to SQLite database (required)")
	repoPath := flag.String("repo", ".", "Repo root path for path normalisation")
	flag.Parse()

	if *dbPath == "" {
		fmt.Fprintln(os.Stderr, "error: --db is required")
		os.Exit(1)
	}

	s, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer s.Close()

	srv := mcpserver.New(s, *repoPath)

	mcpSrv := mcp.NewServer(&mcp.Implementation{
		Name:    "council",
		Version: "0.1.0",
	}, nil)
	srv.Register(mcpSrv)

	log.Printf("council-mcp starting, db=%s repo=%s", *dbPath, *repoPath)
	if err := mcpSrv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
