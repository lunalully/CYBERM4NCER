package core

import (
	"context"
	"fmt"

	"github.com/lunalully/cyberm4ncer/internal/aggressive"
	"github.com/lunalully/cyberm4ncer/internal/execution"
	"github.com/lunalully/cyberm4ncer/internal/scope"
)

// AggressiveService wires the aggressive engine to the core execution entry
// point. When a scope policy is supplied every planned command is checked
// against it; without one the commands run against the target given.
type AggressiveService struct {
	core     *Core
	executor *aggressive.Executor
	planner  *aggressive.Planner
	policy   *scope.Policy
}

// NewAggressive returns an aggressive service for the given mode.
func (c *Core) NewAggressive(mode aggressive.Mode) (*AggressiveService, error) {
	if c == nil || c.Tools == nil {
		return nil, fmt.Errorf("aggressive service requires a tool registry")
	}
	service := &AggressiveService{
		core:    c,
		planner: &aggressive.Planner{Registry: c.Tools, Mode: mode},
	}
	service.executor = &aggressive.Executor{
		Execute: func(ctx context.Context, req execution.Request) (execution.Result, error) {
			// A nil policy means the operator supplied no scope file.
			return c.ExecuteScoped(ctx, service.policy, req)
		},
		Registry: c.Tools,
	}
	return service, nil
}

// Plan builds the full command plan for a target. A nil policy means no
// scope: the plan addresses the target as given.
func (s *AggressiveService) Plan(target string, policy *scope.Policy) (*aggressive.Plan, error) {
	return s.planner.Plan(target, policy)
}

// Run executes a plan. The executor re-checks every concrete target.
func (s *AggressiveService) Run(ctx context.Context, plan *aggressive.Plan, op aggressive.Operation) (aggressive.Summary, error) {
	if plan == nil {
		return aggressive.Summary{}, fmt.Errorf("plan is required")
	}
	s.policy = policyOf(plan.Policy)
	return s.executor.Run(ctx, plan, op)
}

// policyOf extracts the scope policy a plan was built with, or nil.
func policyOf(guard aggressive.Guard) *scope.Policy {
	if adapter, ok := guard.(interface{ ScopePolicy() *scope.Policy }); ok {
		return adapter.ScopePolicy()
	}
	return nil
}
