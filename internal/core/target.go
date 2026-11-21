package core

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lunalully/cyberm4ncer/internal/execution"
	"github.com/lunalully/cyberm4ncer/internal/scope"
)

var (
	// ErrScopeRequired prevents target-facing execution without a policy.
	ErrScopeRequired = errors.New("scope policy is required for target-facing execution")
	// ErrTargetRequired prevents execution without an auditable target.
	ErrTargetRequired = errors.New("target is required for target-facing execution")
)

// ScopeDeniedError reports a target rejected by the scope policy.
type ScopeDeniedError struct {
	Decision scope.Decision
}

func (e *ScopeDeniedError) Error() string {
	return fmt.Sprintf("scope denied: %s (%s)", e.Decision.Target, e.Decision.Reason)
}

// ExecuteScoped is the only target-facing execution entry point.
//
// It fails closed: a missing policy, missing target, denied scope or audit
// failure prevents the process from running. The raw runner is private to the
// core so modules cannot bypass this check accidentally.
func (c *Core) ExecuteScoped(ctx context.Context, policy *scope.Policy, request execution.Request) (execution.Result, error) {
	if policy == nil {
		return execution.Result{}, ErrScopeRequired
	}
	request.Target = strings.TrimSpace(request.Target)
	if request.Target == "" {
		return execution.Result{}, ErrTargetRequired
	}
	decision, err := policy.CheckTarget(request.Target)
	if err != nil {
		return execution.Result{}, fmt.Errorf("evaluate scope for %q: %w", request.Target, err)
	}
	if !decision.Allowed {
		auditErr := c.DB.AppendAudit(ctx, "core", "scope.denied", decision.Target, map[string]any{
			"tool": request.Tool, "reason": decision.Reason, "rule": decision.Rule,
		})
		if auditErr != nil {
			return execution.Result{}, fmt.Errorf("record scope denial: %w", auditErr)
		}
		return execution.Result{}, &ScopeDeniedError{Decision: decision}
	}
	if err := c.DB.AppendAudit(ctx, "core", "scope.allowed", decision.Target, map[string]any{
		"tool": request.Tool, "reason": decision.Reason, "rule": decision.Rule,
	}); err != nil {
		return execution.Result{}, fmt.Errorf("record scope authorization: %w", err)
	}
	return c.runner.Run(ctx, request)
}
