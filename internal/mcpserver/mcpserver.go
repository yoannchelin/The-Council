// Package mcpserver implements the 2 MCP tools: assess_repo and explain_zone.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yoannchl/the-council/internal/correlate"
	"github.com/yoannchl/the-council/internal/report"
	"github.com/yoannchl/the-council/internal/signals"
	"github.com/yoannchl/the-council/internal/store"
)

// AssessRepoInput is the typed input for assess_repo.
type AssessRepoInput struct {
	TopN        int      `json:"top_n"`
	MinPriority float64  `json:"min_priority"`
	SkipPaths   []string `json:"skip_paths"` // path prefixes to exclude, e.g. ["test/", "vendor/"]
}

// ExplainZoneInput is the typed input for explain_zone.
type ExplainZoneInput struct {
	Path      string `json:"path"`
	Qualified string `json:"qualified"`
}

// Server holds the shared state for the MCP server.
type Server struct {
	store    *store.Store
	repoPath string
}

func New(s *store.Store, repoPath string) *Server {
	return &Server{store: s, repoPath: repoPath}
}

func (srv *Server) Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "assess_repo",
		Description: "Run a full multi-signal assessment of the repository and return prioritised action items.",
		InputSchema: rawSchema(map[string]any{
			"type": "object",
			"properties": map[string]any{
				"top_n":        map[string]any{"type": "integer", "description": "Number of action items to return (default 10)"},
				"min_priority": map[string]any{"type": "number", "description": "Minimum priority score 0..1 (default 0)"},
				"skip_paths":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Path prefixes to exclude, e.g. [\"test/\", \"vendor/\"]"},
			},
		}),
	}, mcp.ToolHandlerFor[AssessRepoInput, any](srv.assessRepo))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "explain_zone",
		Description: "Explain why a specific file or symbol is flagged, listing the contributing signals.",
		InputSchema: rawSchema(map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path":      map[string]any{"type": "string", "description": "File path (partial match)"},
				"qualified": map[string]any{"type": "string", "description": "Qualified symbol name (partial match)"},
			},
		}),
	}, mcp.ToolHandlerFor[ExplainZoneInput, any](srv.explainZone))
}

func (srv *Server) assessRepo(_ context.Context, _ *mcp.CallToolRequest, input AssessRepoInput) (*mcp.CallToolResult, any, error) {
	topN := input.TopN
	if topN <= 0 {
		topN = 10
	}

	zones, missing, err := signals.Collect(srv.store, srv.repoPath)
	if err != nil {
		return nil, nil, fmt.Errorf("collect signals: %w", err)
	}

	scored := correlate.Rank(zones, input.MinPriority, input.SkipPaths)
	present := presentAgents(srv.store)
	a := report.Build(scored, present, missing, topN)

	summary := map[string]any{
		"total_zones":       len(zones),
		"scored_zones":      len(scored),
		"convergence_zones": len(a.ConvergenceZones),
	}
	assessRec := &store.Assessment{
		RepoPath:      srv.repoPath,
		AgentsPresent: present,
		Summary:       summary,
		HealthScore:   a.HealthScore,
	}
	assessID, err := srv.store.SaveAssessment(assessRec)
	if err == nil {
		srv.store.SaveActionItems(report.ToStoreItems(assessID, a.TopItems))
	}

	result := map[string]any{
		"health_score":      a.HealthScore,
		"agents_present":    a.AgentsPresent,
		"missing_agents":    a.MissingAgents,
		"top_action_items":  a.TopItems,
		"signal_summary":    a.SignalSummary,
		"convergence_zones": a.ConvergenceZones,
	}
	return toolJSON(result), nil, nil
}

func (srv *Server) explainZone(_ context.Context, _ *mcp.CallToolRequest, input ExplainZoneInput) (*mcp.CallToolResult, any, error) {
	if input.Path == "" && input.Qualified == "" {
		return nil, nil, fmt.Errorf("provide 'path' or 'qualified'")
	}

	zones, _, err := signals.Collect(srv.store, srv.repoPath)
	if err != nil {
		return nil, nil, fmt.Errorf("collect signals: %w", err)
	}

	type zoneExplanation struct {
		Path          string   `json:"path"`
		Qualified     string   `json:"qualified"`
		PriorityScore float64  `json:"priority_score"`
		SignalCount   int      `json:"signal_count"`
		Blast         float64  `json:"blast_score"`
		SentinelGap   float64  `json:"sentinel_gap"`
		HunterScore   float64  `json:"hunter_score"`
		DepVulnScore  float64  `json:"dep_vuln_score"`
		DepVulnIDs    []string `json:"dep_vuln_ids,omitempty"`
	}

	var explanations []zoneExplanation
	for _, z := range zones {
		match := false
		if input.Path != "" && strings.Contains(z.Path, input.Path) {
			match = true
		}
		if input.Qualified != "" && strings.Contains(z.Qualified, input.Qualified) {
			match = true
		}
		if !match {
			continue
		}
		explanations = append(explanations, zoneExplanation{
			Path:          z.Path,
			Qualified:     z.Qualified,
			PriorityScore: correlate.Score(z),
			SignalCount:   z.SignalCount,
			Blast:         z.BlastScore,
			SentinelGap:   z.SentinelGap,
			HunterScore:   z.HunterScore,
			DepVulnScore:  z.DepVulnScore,
			DepVulnIDs:    z.DepVulnIDs,
		})
	}

	if len(explanations) == 0 {
		return toolJSON(map[string]any{"found": false, "message": "no zone matched"}), nil, nil
	}
	return toolJSON(map[string]any{"found": true, "zones": explanations}), nil, nil
}

func presentAgents(s *store.Store) []string {
	p := s.AgentsPresent()
	var out []string
	for name, ok := range p {
		if ok {
			out = append(out, name)
		}
	}
	return out
}

func toolJSON(v any) *mcp.CallToolResult {
	b, _ := json.Marshal(v)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(b)},
		},
	}
}

func rawSchema(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
