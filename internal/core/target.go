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

// ExecuteScoped is the target-facing execution entry point.
//
// The scope policy is optional: with a policy every target is checked and the
// decision is audited; without one the target is used as given and the run is
// audited as unscoped. A missing target or an audit failure still prevents the
// process from running.
func (c *Core) ExecuteScoped(ctx context.Context, policy *scope.Policy, request execution.Request) (execution.Result, error) {
	request.Target = strings.TrimSpace(request.Target)
	if request.Target == "" {
		return execution.Result{}, ErrTargetRequired
	}
	if policy == nil {
		if err := c.DB.AppendAudit(ctx, "core", "scope.unscoped", request.Target, map[string]any{
			"tool": request.Tool,
		}); err != nil {
			return execution.Result{}, fmt.Errorf("record unscoped execution: %w", err)
		}
		return c.runner.Run(ctx, request)
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
