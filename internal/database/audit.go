package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// AuditEntry is one tamper-evident audit record.
type AuditEntry struct {
	Seq       int64           `json:"seq"`
	Timestamp time.Time       `json:"timestamp"`
	Actor     string          `json:"actor"`
	Action    string          `json:"action"`
	Target    string          `json:"target"`
	Detail    json.RawMessage `json:"detail"`
	PrevHash  string          `json:"prev_hash"`
	Hash      string          `json:"hash"`
}

// AppendAudit adds an entry to the hash chain. Detail is canonicalized as
// compact JSON; nil is stored as {}.
func (s *Store) AppendAudit(ctx context.Context, actor, action, target string, detail any) error {
	if actor == "" || action == "" {
		return fmt.Errorf("audit actor and action are required")
	}
	encoded, err := canonicalDetail(detail)
	if err != nil {
		return err
	}
	now := time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin audit transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var prevHash string
	err = tx.QueryRowContext(ctx, `SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&prevHash)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read previous audit hash: %w", err)
		}
		prevHash = genesisHash
	}
	hash := hashAudit(prevHash, now, actor, action, target, encoded)
	_, err = tx.ExecContext(ctx,
		`INSERT INTO audit_log (ts, actor, action, target, detail_json, prev_hash, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		formatTime(now), actor, action, target, encoded, prevHash, hash,
	)
	if err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit entry: %w", err)
	}
	return nil
}

// AuditVerification describes chain integrity.
type AuditVerification struct {
	Entries  int   `json:"entries"`
	Valid    bool  `json:"valid"`
	BrokenAt int64 `json:"broken_at,omitempty"`
}

// VerifyAudit recomputes the chain and reports the first broken sequence.
func (s *Store) VerifyAudit(ctx context.Context) (AuditVerification, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, ts, actor, action, target, detail_json, prev_hash, hash
		 FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return AuditVerification{}, fmt.Errorf("read audit log: %w", err)
	}
	defer rows.Close()

	verification := AuditVerification{Valid: true}
	expectedPrev := genesisHash
	for rows.Next() {
		var seq int64
		var ts, actor, action, target, detail, prevHash, hash string
		if err := rows.Scan(&seq, &ts, &actor, &action, &target, &detail, &prevHash, &hash); err != nil {
			return AuditVerification{}, fmt.Errorf("scan audit entry: %w", err)
		}
		verification.Entries++
		timestamp, err := parseTime(ts)
		if err != nil {
			return AuditVerification{}, err
		}
		expectedHash := hashAudit(expectedPrev, timestamp, actor, action, target, detail)
		if prevHash != expectedPrev || hash != expectedHash {
			verification.Valid = false
			verification.BrokenAt = seq
			return verification, nil
		}
		expectedPrev = hash
	}
	if err := rows.Err(); err != nil {
		return AuditVerification{}, fmt.Errorf("iterate audit log: %w", err)
	}
	return verification, nil
}

func canonicalDetail(detail any) (string, error) {
	if detail == nil {
		return "{}", nil
	}
	encoded, err := json.Marshal(detail)
	if err != nil {
		return "", fmt.Errorf("encode audit detail: %w", err)
	}
	return string(encoded), nil
}

func hashAudit(prevHash string, timestamp time.Time, actor, action, target, detail string) string {
	digest := sha256.New()
	for _, part := range []string{
		prevHash,
		formatTime(timestamp),
		actor,
		action,
		target,
		detail,
	} {
		_, _ = digest.Write([]byte(part))
		_, _ = digest.Write([]byte{'\n'})
	}
	return hex.EncodeToString(digest.Sum(nil))
}
