package core

import (
	"context"

	"github.com/lunalully/cyberm4ncer/internal/aggressive"
	"github.com/lunalully/cyberm4ncer/internal/execution"
	"github.com/lunalully/cyberm4ncer/internal/scope"
)

// AggressiveService wires the aggressive engine to the scoped execution
// entry point. Every planned command is still checked against the scope
// policy and recorded before it runs.
type AggressiveService struct {
	core     *Core
	executor *aggressive.Executor
	planner  *aggressive.Planner
	policy   *scope.Policy
}

// NewAggressive returns an aggressive service for the given mode.
func (c *Core) NewAggressive(mode aggressive.Mode) (*AggressiveService, error) {
	if c == nil || c.Tools == nil {
		return nil, ErrScopeRequired
	}
	service := &AggressiveService{
		core:    c,
		planner: &aggressive.Planner{Registry: c.Tools, Mode: mode},
	}
	service.executor = &aggressive.Executor{
		Execute: func(ctx context.Context, req execution.Request) (execution.Result, error) {
			// Run uses a non-nil policy; ExecuteScoped refuses nil.
			return c.ExecuteScoped(ctx, service.policy, req)
		},
		Registry: c.Tools,
	}
	return service, nil
}

// Plan builds the full command plan for a target after checking scope.
func (s *AggressiveService) Plan(target string, policy *scope.Policy) (*aggressive.Plan, error) {
	return s.planner.Plan(target, policy)
}

// Run executes a plan. The executor re-checks every concrete target.
func (s *AggressiveService) Run(ctx context.Context, plan *aggressive.Plan, op aggressive.Operation) (aggressive.Summary, error) {
	if plan == nil || plan.Policy == nil {
		return aggressive.Summary{}, ErrScopeRequired
	}
	s.policy = plan.Policy
	return s.executor.Run(ctx, plan, op)
}
