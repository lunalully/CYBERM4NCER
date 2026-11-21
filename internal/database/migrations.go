package database

// migrations is append-only. Never edit a migration that has shipped.
var migrations = []string{
	`
CREATE TABLE projects (
	id          TEXT PRIMARY KEY,
	name        TEXT NOT NULL UNIQUE,
	description TEXT NOT NULL DEFAULT '',
	created_at  TEXT NOT NULL
);

CREATE TABLE operations (
	id          TEXT PRIMARY KEY,
	project_id  TEXT REFERENCES projects(id) ON DELETE SET NULL,
	kind        TEXT NOT NULL,
	target      TEXT NOT NULL DEFAULT '',
	profile     TEXT NOT NULL DEFAULT '',
	status      TEXT NOT NULL,
	started_at  TEXT NOT NULL,
	finished_at TEXT,
	error       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_operations_project ON operations(project_id);
CREATE INDEX idx_operations_started ON operations(started_at);

CREATE TABLE executions (
	id             TEXT PRIMARY KEY,
	operation_id   TEXT REFERENCES operations(id) ON DELETE SET NULL,
	tool           TEXT NOT NULL,
	target         TEXT NOT NULL DEFAULT '',
	argv_json      TEXT NOT NULL DEFAULT '[]',
	status         TEXT NOT NULL,
	exit_code      INTEGER NOT NULL DEFAULT -1,
	started_at     TEXT NOT NULL,
	finished_at    TEXT,
	timeout_ms     INTEGER NOT NULL DEFAULT 0,
	stdout_path    TEXT NOT NULL DEFAULT '',
	stderr_path    TEXT NOT NULL DEFAULT '',
	stdout_preview TEXT NOT NULL DEFAULT '',
	stderr_preview TEXT NOT NULL DEFAULT '',
	error          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_executions_operation ON executions(operation_id);
CREATE INDEX idx_executions_started ON executions(started_at);

CREATE TABLE results (
	id           TEXT PRIMARY KEY,
	project_id   TEXT REFERENCES projects(id) ON DELETE CASCADE,
	operation_id TEXT REFERENCES operations(id) ON DELETE SET NULL,
	execution_id TEXT REFERENCES executions(id) ON DELETE SET NULL,
	asset        TEXT NOT NULL,
	kind         TEXT NOT NULL,
	source       TEXT NOT NULL DEFAULT '',
	tool         TEXT NOT NULL DEFAULT '',
	severity     TEXT NOT NULL DEFAULT 'unknown',
	title        TEXT NOT NULL,
	description  TEXT NOT NULL DEFAULT '',
	evidence     TEXT NOT NULL DEFAULT '',
	data_json    TEXT NOT NULL DEFAULT '{}',
	fingerprint  TEXT NOT NULL,
	validated    INTEGER NOT NULL DEFAULT 0,
	created_at   TEXT NOT NULL,
	last_seen_at TEXT NOT NULL
);
CREATE INDEX idx_results_project ON results(project_id);
CREATE INDEX idx_results_operation ON results(operation_id);
CREATE INDEX idx_results_fingerprint ON results(project_id, fingerprint);

CREATE TABLE audit_log (
	seq         INTEGER PRIMARY KEY AUTOINCREMENT,
	ts          TEXT NOT NULL,
	actor       TEXT NOT NULL,
	action      TEXT NOT NULL,
	target      TEXT NOT NULL DEFAULT '',
	detail_json TEXT NOT NULL DEFAULT '{}',
	prev_hash   TEXT NOT NULL,
	hash        TEXT NOT NULL
);
`,
}
