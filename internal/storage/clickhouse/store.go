package clickhouse

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"

	"iam-audit/internal/domain"
	"iam-audit/internal/proto/auditcodec"
)

type Config struct {
	Address         string
	Database        string
	Username        string
	Password        string
	SchemaValidator SchemaValidator
}

type Store struct {
	conn            ch.Conn
	appendMu        sync.Mutex
	schemaValidator SchemaValidator
}

type SchemaValidator interface {
	Validate(context.Context, string, string) error
}

func NewStore(ctx context.Context, cfg Config) (*Store, error) {
	conn, err := ch.Open(&ch.Options{
		Addr: []string{cfg.Address},
		Auth: ch.Auth{
			Database: cfg.Database,
			Username: cfg.Username,
			Password: cfg.Password,
		},
	})
	if err != nil {
		return nil, err
	}
	var pingErr error
	for i := 0; i < 30; i++ {
		if pingErr = conn.Ping(ctx); pingErr == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if pingErr != nil {
		return nil, pingErr
	}
	s := &Store{conn: conn, schemaValidator: cfg.SchemaValidator}
	if err := s.migrate(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS audit_events (
			id String,
			schema_id String,
			schema_version LowCardinality(String),
			event_type LowCardinality(String),
			source LowCardinality(String),
			correlation_id String,
			trace_id String,
			ticket_id String,
			actor_id String,
			actor_type LowCardinality(String),
			actor_display_name String,
			subject_id String,
			subject_type LowCardinality(String),
			subject_display_name String,
			resource_system LowCardinality(String),
			resource_role String,
			resource_path String,
			resource_environment LowCardinality(String),
			resource_criticality LowCardinality(String),
			action LowCardinality(String),
			decision LowCardinality(String),
			reason String,
			timestamp DateTime64(9, 'UTC'),
			received_at DateTime64(9, 'UTC'),
			prev_hash String,
			hash String,
			payload String,
			search_text String
		)
		ENGINE = MergeTree
		PARTITION BY toYYYYMM(timestamp)
		ORDER BY (timestamp, actor_id, subject_id, resource_system, action, decision, correlation_id)
		SETTINGS index_granularity = 8192`,
		`CREATE TABLE IF NOT EXISTS audit_event_fields (
			event_id String,
			field_path String,
			field_value String,
			field_type LowCardinality(String),
			timestamp DateTime64(9, 'UTC')
		)
		ENGINE = MergeTree
		PARTITION BY toYYYYMM(timestamp)
		ORDER BY (field_path, field_value, timestamp, event_id)`,
		`CREATE TABLE IF NOT EXISTS access_log (
			id String,
			timestamp DateTime64(9, 'UTC'),
			actor String,
			operation LowCardinality(String),
			target String,
			query String
		)
		ENGINE = MergeTree
		PARTITION BY toYYYYMM(timestamp)
		ORDER BY (timestamp, actor, operation)`,
	}
	for _, statement := range statements {
		if err := s.conn.Exec(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) EventCount() int {
	var count uint64
	_ = s.conn.QueryRow(context.Background(), "SELECT count() FROM audit_events").Scan(&count)
	return int(count)
}

func (s *Store) AppendEvent(e *domain.Envelope) error {
	if err := validateEnvelope(e); err != nil {
		return err
	}
	if s.schemaValidator != nil {
		if err := s.schemaValidator.Validate(context.Background(), e.SchemaID, e.SchemaVersion); err != nil {
			return err
		}
	}
	s.appendMu.Lock()
	defer s.appendMu.Unlock()

	ctx := context.Background()
	if e.ID == "" {
		e.ID = newID()
	}
	if e.ReceivedAt.IsZero() {
		e.ReceivedAt = time.Now().UTC()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = e.ReceivedAt
	}
	if err := auditcodec.EnsureAccessLifecyclePayload(e); err != nil {
		return err
	}
	prevHash, err := s.lastHash(ctx)
	if err != nil {
		return err
	}
	e.PrevHash = prevHash
	e.Hash = hashEvent(*e)
	payload, err := auditcodec.MarshalEnvelope(*e)
	if err != nil {
		return err
	}
	err = s.conn.Exec(ctx, `INSERT INTO audit_events (
		id, schema_id, schema_version, event_type, source, correlation_id, trace_id, ticket_id,
		actor_id, actor_type, actor_display_name,
		subject_id, subject_type, subject_display_name,
		resource_system, resource_role, resource_path, resource_environment, resource_criticality,
		action, decision, reason, timestamp, received_at, prev_hash, hash, payload, search_text
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.SchemaID, e.SchemaVersion, e.EventType, e.Source, e.CorrelationID, e.TraceID, e.TicketID,
		e.Actor.ID, e.Actor.Type, e.Actor.DisplayName,
		e.Subject.ID, e.Subject.Type, e.Subject.DisplayName,
		e.Resource.System, e.Resource.Role, e.Resource.Path, e.Resource.Environment, e.Resource.Criticality,
		e.Action, e.Decision, e.Reason, e.Timestamp.UTC(), e.ReceivedAt.UTC(), e.PrevHash, e.Hash, string(payload), searchableText(*e),
	)
	if err != nil {
		return err
	}
	return s.insertFields(ctx, *e)
}

func (s *Store) Search(f domain.Filter) []domain.Envelope {
	query, args := searchQuery(f)
	rows, err := s.conn.Query(context.Background(), query, args...)
	if err != nil {
		return []domain.Envelope{}
	}
	defer rows.Close()
	out := []domain.Envelope{}
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			continue
		}
		e, err := auditcodec.UnmarshalEnvelope([]byte(payload))
		if err == nil {
			out = append(out, e)
		}
	}
	return out
}

func (s *Store) Correlation(id string) []domain.Envelope {
	rows, err := s.conn.Query(context.Background(), `SELECT payload FROM audit_events
		WHERE correlation_id = ? OR trace_id = ? OR ticket_id = ?
		ORDER BY timestamp ASC LIMIT 500`, id, id, id)
	if err != nil {
		return []domain.Envelope{}
	}
	defer rows.Close()
	out := []domain.Envelope{}
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			continue
		}
		e, err := auditcodec.UnmarshalEnvelope([]byte(payload))
		if err == nil {
			out = append(out, e)
		}
	}
	return out
}

func (s *Store) VerifyHashChain() (bool, string) {
	rows, err := s.conn.Query(context.Background(), "SELECT payload FROM audit_events ORDER BY received_at ASC, id ASC")
	if err != nil {
		return false, ""
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return false, ""
		}
		e, err := auditcodec.UnmarshalEnvelope([]byte(payload))
		if err != nil {
			return false, ""
		}
		if e.PrevHash != prev || hashEvent(e) != e.Hash {
			return false, e.ID
		}
		prev = e.Hash
	}
	return true, ""
}

func (s *Store) Seed() error {
	for _, e := range domain.SampleEvents() {
		if !s.hasDuplicate(e) {
			if err := s.AppendEvent(&e); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) AccessLog() []domain.AccessLogEntry {
	rows, err := s.conn.Query(context.Background(), "SELECT id, timestamp, actor, operation, target, query FROM access_log ORDER BY timestamp DESC LIMIT 200")
	if err != nil {
		return []domain.AccessLogEntry{}
	}
	defer rows.Close()
	out := []domain.AccessLogEntry{}
	for rows.Next() {
		var e domain.AccessLogEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Actor, &e.Operation, &e.Target, &e.Query); err == nil {
			out = append(out, e)
		}
	}
	return out
}

func (s *Store) LogAccess(entry domain.AccessLogEntry) {
	_ = s.conn.Exec(context.Background(), "INSERT INTO access_log (id, timestamp, actor, operation, target, query) VALUES (?, ?, ?, ?, ?, ?)",
		entry.ID, entry.Timestamp.UTC(), entry.Actor, entry.Operation, entry.Target, entry.Query)
}

func (s *Store) lastHash(ctx context.Context) (string, error) {
	var hash string
	err := s.conn.QueryRow(ctx, "SELECT hash FROM audit_events ORDER BY received_at DESC, id DESC LIMIT 1").Scan(&hash)
	if err != nil && strings.Contains(err.Error(), "no rows") {
		return "", nil
	}
	return hash, err
}

func (s *Store) hasDuplicate(e domain.Envelope) bool {
	var count uint64
	_ = s.conn.QueryRow(context.Background(), `SELECT count() FROM audit_events
		WHERE ticket_id = ? AND action = ? AND subject_id = ? AND resource_path = ?`,
		e.TicketID, e.Action, e.Subject.ID, e.Resource.Path).Scan(&count)
	return count > 0
}

func searchQuery(f domain.Filter) (string, []any) {
	conditions := []string{"1 = 1"}
	args := []any{}
	add := func(condition string, value any) {
		conditions = append(conditions, condition)
		args = append(args, value)
	}
	if f.Actor != "" {
		add("(actor_id ILIKE ? OR actor_display_name ILIKE ?)", "%"+f.Actor+"%")
		args = append(args, "%"+f.Actor+"%")
	}
	if f.Subject != "" {
		add("(subject_id ILIKE ? OR subject_display_name ILIKE ?)", "%"+f.Subject+"%")
		args = append(args, "%"+f.Subject+"%")
	}
	if f.ResourcePath != "" {
		add("resource_path ILIKE ?", "%"+f.ResourcePath+"%")
	}
	if f.Action != "" {
		add("action = ?", f.Action)
	}
	if f.Decision != "" {
		add("decision = ?", f.Decision)
	}
	if f.System != "" {
		add("resource_system = ?", f.System)
	}
	if f.Environment != "" {
		add("resource_environment = ?", f.Environment)
	}
	if f.CorrelationID != "" {
		add("correlation_id = ?", f.CorrelationID)
	}
	if f.TraceID != "" {
		add("trace_id = ?", f.TraceID)
	}
	if f.TicketID != "" {
		add("ticket_id = ?", f.TicketID)
	}
	if !f.From.IsZero() {
		add("timestamp >= ?", f.From.UTC())
	}
	if !f.To.IsZero() {
		add("timestamp <= ?", f.To.UTC())
	}
	if f.Query != "" {
		add(`(search_text ILIKE ? OR id IN (
			SELECT event_id FROM audit_event_fields WHERE field_value ILIKE ?
		))`, "%"+f.Query+"%")
		args = append(args, "%"+f.Query+"%")
	}
	if f.FieldPath != "" {
		add("id IN (SELECT event_id FROM audit_event_fields WHERE field_path = ?)", f.FieldPath)
	}
	if f.FieldValue != "" {
		add("id IN (SELECT event_id FROM audit_event_fields WHERE field_value ILIKE ?)", "%"+f.FieldValue+"%")
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := fmt.Sprintf("SELECT payload FROM audit_events WHERE %s ORDER BY timestamp DESC LIMIT ? OFFSET ?",
		strings.Join(conditions, " AND "))
	args = append(args, limit, f.Offset)
	return query, args
}

func (s *Store) insertFields(ctx context.Context, e domain.Envelope) error {
	fields := indexedFields(e)
	if len(fields) == 0 {
		return nil
	}
	batch, err := s.conn.PrepareBatch(ctx, "INSERT INTO audit_event_fields (event_id, field_path, field_value, field_type, timestamp)")
	if err != nil {
		return err
	}
	for path, value := range fields {
		if err := batch.Append(e.ID, path, value, "string", e.Timestamp.UTC()); err != nil {
			return err
		}
	}
	return batch.Send()
}

func indexedFields(e domain.Envelope) map[string]string {
	fields := map[string]string{
		"schema.id":            e.SchemaID,
		"schema.version":       e.SchemaVersion,
		"event.type":           e.EventType,
		"actor.id":             e.Actor.ID,
		"actor.type":           e.Actor.Type,
		"actor.display_name":   e.Actor.DisplayName,
		"subject.id":           e.Subject.ID,
		"subject.type":         e.Subject.Type,
		"subject.display_name": e.Subject.DisplayName,
		"resource.system":      e.Resource.System,
		"resource.role":        e.Resource.Role,
		"resource.path":        e.Resource.Path,
		"resource.environment": e.Resource.Environment,
		"action":               e.Action,
		"decision":             e.Decision,
	}
	for k, v := range e.Extensions {
		fields["extensions."+k] = v
	}
	for k, v := range e.Actor.Attributes {
		fields["actor.attributes."+k] = v
	}
	for k, v := range e.Subject.Attributes {
		fields["subject.attributes."+k] = v
	}
	for k, v := range e.Resource.Attributes {
		fields["resource.attributes."+k] = v
	}
	for k, v := range e.Fields {
		fields[k] = v
	}
	for k, v := range fields {
		if v == "" {
			delete(fields, k)
		}
	}
	return fields
}

func validateEnvelope(e *domain.Envelope) error {
	required := map[string]string{
		"schema_version": e.SchemaVersion,
		"event_type":     e.EventType,
		"source":         e.Source,
		"actor.id":       e.Actor.ID,
		"subject.id":     e.Subject.ID,
		"resource.path":  e.Resource.Path,
		"action":         e.Action,
		"decision":       e.Decision,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("required field is empty: %s", field)
		}
	}
	return nil
}

func hashEvent(e domain.Envelope) string {
	payload, _ := auditcodec.MarshalEnvelopeForHash(e)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func searchableText(e domain.Envelope) string {
	parts := []string{
		e.ID, e.SchemaVersion, e.EventType, e.Source, e.CorrelationID, e.TraceID, e.TicketID,
		e.Actor.ID, e.Actor.Type, e.Actor.DisplayName,
		e.Subject.ID, e.Subject.Type, e.Subject.DisplayName,
		e.Resource.System, e.Resource.Role, e.Resource.Path, e.Resource.Environment, e.Resource.Criticality,
		e.Action, e.Decision, e.Reason, e.PrevHash, e.Hash,
	}
	for k, v := range e.Extensions {
		parts = append(parts, k, v)
	}
	for k, v := range e.Fields {
		parts = append(parts, k, v)
	}
	for k, v := range e.Actor.Attributes {
		parts = append(parts, k, v)
	}
	for k, v := range e.Subject.Attributes {
		parts = append(parts, k, v)
	}
	for k, v := range e.Resource.Attributes {
		parts = append(parts, k, v)
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

func newID() string {
	return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
}
