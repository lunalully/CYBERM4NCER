package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Project groups operations and results for one engagement.
type Project struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// CreateProject inserts a project.
func (s *Store) CreateProject(ctx context.Context, project Project) error {
	if project.ID == "" || project.Name == "" {
		return fmt.Errorf("project id and name are required")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO projects (id, name, description, created_at) VALUES (?, ?, ?, ?)`,
		project.ID, project.Name, project.Description, formatTime(project.CreatedAt),
	)
	if err != nil {
		return fmt.Errorf("create project: %w", err)
	}
	return nil
}

// GetProjectByName loads a project by its unique name.
func (s *Store) GetProjectByName(ctx context.Context, name string) (Project, error) {
	var project Project
	var createdAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, description, created_at FROM projects WHERE name = ?`, name,
	).Scan(&project.ID, &project.Name, &project.Description, &createdAt)
	if err != nil {
		return Project{}, fmt.Errorf("get project %q: %w", name, err)
	}
	project.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return Project{}, err
	}
	return project, nil
}

// Operation is a logical unit of work such as a scan or workflow run.
type Operation struct {
	ID         string     `json:"id"`
	ProjectID  string     `json:"project_id,omitempty"`
	Kind       string     `json:"kind"`
	Target     string     `json:"target"`
	Profile    string     `json:"profile,omitempty"`
	Status     string     `json:"status"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// CreateOperation inserts an operation.
func (s *Store) CreateOperation(ctx context.Context, operation Operation) error {
	if operation.ID == "" || operation.Kind == "" {
		return fmt.Errorf("operation id and kind are required")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO operations (id, project_id, kind, target, profile, status, started_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		operation.ID, nullString(operation.ProjectID), operation.Kind, operation.Target,
		operation.Profile, operation.Status, formatTime(operation.StartedAt),
	)
	if err != nil {
		return fmt.Errorf("create operation: %w", err)
	}
	return nil
}

// FinishOperation records the terminal state of an operation.
func (s *Store) FinishOperation(ctx context.Context, id, status string, finishedAt time.Time, errMessage string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE operations SET status = ?, finished_at = ?, error = ? WHERE id = ?`,
		status, formatTime(finishedAt), errMessage, id,
	)
	if err != nil {
		return fmt.Errorf("finish operation: %w", err)
	}
	if err := requireOneRow(result); err != nil {
		return fmt.Errorf("finish operation %s: %w", id, err)
	}
	return nil
}

// GetOperation loads one operation.
func (s *Store) GetOperation(ctx context.Context, id string) (Operation, error) {
	var operation Operation
	var projectID, finishedAt sql.NullString
	var startedAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, project_id, kind, target, profile, status, started_at, finished_at, error
		 FROM operations WHERE id = ?`, id,
	).Scan(&operation.ID, &projectID, &operation.Kind, &operation.Target, &operation.Profile,
		&operation.Status, &startedAt, &finishedAt, &operation.Error)
	if err != nil {
		return Operation{}, fmt.Errorf("get operation %s: %w", id, err)
	}
	operation.ProjectID = projectID.String
	operation.StartedAt, err = parseTime(startedAt)
	if err != nil {
		return Operation{}, err
	}
	if finishedAt.Valid {
		parsed, err := parseTime(finishedAt.String)
		if err != nil {
			return Operation{}, err
		}
		operation.FinishedAt = &parsed
	}
	return operation, nil
}

// ListOperations returns the most recent operations.
func (s *Store) ListOperations(ctx context.Context, limit int) ([]Operation, error) {
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, project_id, kind, target, profile, status, started_at, finished_at, error
		 FROM operations ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list operations: %w", err)
	}
	defer rows.Close()

	var operations []Operation
	for rows.Next() {
		var operation Operation
		var projectID, finishedAt sql.NullString
		var startedAt string
		if err := rows.Scan(&operation.ID, &projectID, &operation.Kind, &operation.Target,
			&operation.Profile, &operation.Status, &startedAt, &finishedAt, &operation.Error); err != nil {
			return nil, fmt.Errorf("scan operation: %w", err)
		}
		operation.ProjectID = projectID.String
		operation.StartedAt, err = parseTime(startedAt)
		if err != nil {
			return nil, err
		}
		if finishedAt.Valid {
			parsed, err := parseTime(finishedAt.String)
			if err != nil {
				return nil, err
			}
			operation.FinishedAt = &parsed
		}
		operations = append(operations, operation)
	}
	return operations, rows.Err()
}

// Execution is the persisted record of one external process.
type Execution struct {
	ID            string     `json:"id"`
	OperationID   string     `json:"operation_id,omitempty"`
	Tool          string     `json:"tool"`
	Target        string     `json:"target"`
	Argv          []string   `json:"argv"`
	Status        string     `json:"status"`
	ExitCode      int        `json:"exit_code"`
	StartedAt     time.Time  `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	TimeoutMS     int64      `json:"timeout_ms"`
	StdoutPath    string     `json:"stdout_path,omitempty"`
	StderrPath    string     `json:"stderr_path,omitempty"`
	StdoutPreview string     `json:"stdout_preview,omitempty"`
	StderrPreview string     `json:"stderr_preview,omitempty"`
	Error         string     `json:"error,omitempty"`
}

// CreateExecution inserts an execution row.
func (s *Store) CreateExecution(ctx context.Context, execution Execution) error {
	if execution.ID == "" || execution.Tool == "" {
		return fmt.Errorf("execution id and tool are required")
	}
	argv := execution.Argv
	if argv == nil {
		argv = []string{}
	}
	encoded, err := json.Marshal(argv)
	if err != nil {
		return fmt.Errorf("encode argv: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO executions
		 (id, operation_id, tool, target, argv_json, status, exit_code, started_at, timeout_ms)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		execution.ID, nullString(execution.OperationID), execution.Tool, execution.Target,
		string(encoded), execution.Status, execution.ExitCode, formatTime(execution.StartedAt), execution.TimeoutMS,
	)
	if err != nil {
		return fmt.Errorf("create execution: %w", err)
	}
	return nil
}

// FinishExecution records the terminal state of an execution.
func (s *Store) FinishExecution(ctx context.Context, execution Execution) error {
	if execution.FinishedAt == nil {
		now := time.Now()
		execution.FinishedAt = &now
	}
	result, err := s.db.ExecContext(ctx,
		`UPDATE executions SET status = ?, exit_code = ?, finished_at = ?, stdout_path = ?,
		 stderr_path = ?, stdout_preview = ?, stderr_preview = ?, error = ? WHERE id = ?`,
		execution.Status, execution.ExitCode, formatTime(*execution.FinishedAt),
		execution.StdoutPath, execution.StderrPath, execution.StdoutPreview,
		execution.StderrPreview, execution.Error, execution.ID,
	)
	if err != nil {
		return fmt.Errorf("finish execution: %w", err)
	}
	if err := requireOneRow(result); err != nil {
		return fmt.Errorf("finish execution %s: %w", execution.ID, err)
	}
	return nil
}

// GetExecution loads one execution.
func (s *Store) GetExecution(ctx context.Context, id string) (Execution, error) {
	var execution Execution
	var operationID, finishedAt sql.NullString
	var argvJSON, startedAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, operation_id, tool, target, argv_json, status, exit_code, started_at,
		 finished_at, timeout_ms, stdout_path, stderr_path, stdout_preview, stderr_preview, error
		 FROM executions WHERE id = ?`, id,
	).Scan(&execution.ID, &operationID, &execution.Tool, &execution.Target, &argvJSON,
		&execution.Status, &execution.ExitCode, &startedAt, &finishedAt, &execution.TimeoutMS,
		&execution.StdoutPath, &execution.StderrPath, &execution.StdoutPreview,
		&execution.StderrPreview, &execution.Error)
	if err != nil {
		return Execution{}, fmt.Errorf("get execution %s: %w", id, err)
	}
	execution.OperationID = operationID.String
	execution.StartedAt, err = parseTime(startedAt)
	if err != nil {
		return Execution{}, err
	}
	if finishedAt.Valid {
		parsed, err := parseTime(finishedAt.String)
		if err != nil {
			return Execution{}, err
		}
		execution.FinishedAt = &parsed
	}
	if err := json.Unmarshal([]byte(argvJSON), &execution.Argv); err != nil {
		return Execution{}, fmt.Errorf("decode argv for %s: %w", id, err)
	}
	return execution, nil
}

// ListExecutions returns the most recent executions.
func (s *Store) ListExecutions(ctx context.Context, limit int) ([]Execution, error) {
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, operation_id, tool, target, argv_json, status, exit_code, started_at,
		 finished_at, timeout_ms, stdout_path, stderr_path, stdout_preview, stderr_preview, error
		 FROM executions ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list executions: %w", err)
	}
	defer rows.Close()

	var executions []Execution
	for rows.Next() {
		var execution Execution
		var operationID, finishedAt sql.NullString
		var argvJSON, startedAt string
		if err := rows.Scan(&execution.ID, &operationID, &execution.Tool, &execution.Target,
			&argvJSON, &execution.Status, &execution.ExitCode, &startedAt, &finishedAt,
			&execution.TimeoutMS, &execution.StdoutPath, &execution.StderrPath,
			&execution.StdoutPreview, &execution.StderrPreview, &execution.Error); err != nil {
			return nil, fmt.Errorf("scan execution: %w", err)
		}
		execution.OperationID = operationID.String
		execution.StartedAt, err = parseTime(startedAt)
		if err != nil {
			return nil, err
		}
		if finishedAt.Valid {
			parsed, err := parseTime(finishedAt.String)
			if err != nil {
				return nil, err
			}
			execution.FinishedAt = &parsed
		}
		if err := json.Unmarshal([]byte(argvJSON), &execution.Argv); err != nil {
			return nil, fmt.Errorf("decode argv for %s: %w", execution.ID, err)
		}
		executions = append(executions, execution)
	}
	return executions, rows.Err()
}

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func requireOneRow(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("record not found")
	}
	return nil
}
