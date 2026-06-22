package httpapi

import (
	"time"

	"iam-audit/internal/domain"
)

type eventView struct {
	ID            string            `json:"id"`
	SchemaID      string            `json:"schema_id,omitempty"`
	SchemaVersion string            `json:"schema_version"`
	EventType     string            `json:"event_type"`
	Source        string            `json:"source"`
	CorrelationID string            `json:"correlation_id,omitempty"`
	TraceID       string            `json:"trace_id,omitempty"`
	TicketID      string            `json:"ticket_id,omitempty"`
	Actor         principalView     `json:"actor"`
	Subject       principalView     `json:"subject"`
	Resource      resourceView      `json:"resource"`
	Action        string            `json:"action"`
	Decision      string            `json:"decision"`
	Reason        string            `json:"reason,omitempty"`
	Timestamp     time.Time         `json:"timestamp"`
	ReceivedAt    time.Time         `json:"received_at"`
	Extensions    map[string]string `json:"extensions,omitempty"`
	Fields        map[string]string `json:"fields,omitempty"`
	PrevHash      string            `json:"prev_hash"`
	Hash          string            `json:"hash"`
}

type principalView struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	DisplayName string            `json:"display_name,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
}

type resourceView struct {
	System      string            `json:"system"`
	Role        string            `json:"role,omitempty"`
	Path        string            `json:"path"`
	Environment string            `json:"environment,omitempty"`
	Criticality string            `json:"criticality,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
}

type accessLogView struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`
	Operation string    `json:"operation"`
	Target    string    `json:"target"`
	Query     string    `json:"query,omitempty"`
}

type adminEventRequest struct {
	SchemaID            string            `json:"schema_id"`
	SchemaVersion       string            `json:"schema_version"`
	EventType           string            `json:"event_type"`
	Source              string            `json:"source"`
	CorrelationID       string            `json:"correlation_id"`
	TraceID             string            `json:"trace_id"`
	TicketID            string            `json:"ticket_id"`
	ActorID             string            `json:"actor_id"`
	ActorType           string            `json:"actor_type"`
	ActorDisplayName    string            `json:"actor_display_name"`
	SubjectID           string            `json:"subject_id"`
	SubjectType         string            `json:"subject_type"`
	SubjectDisplayName  string            `json:"subject_display_name"`
	ResourceSystem      string            `json:"resource_system"`
	ResourceRole        string            `json:"resource_role"`
	ResourcePath        string            `json:"resource_path"`
	ResourceEnv         string            `json:"resource_environment"`
	ResourceCriticality string            `json:"resource_criticality"`
	Action              string            `json:"action"`
	Decision            string            `json:"decision"`
	Reason              string            `json:"reason"`
	Fields              map[string]string `json:"fields"`
	Extensions          map[string]string `json:"extensions"`
}

func (r adminEventRequest) toEnvelope() domain.Envelope {
	schemaVersion := r.SchemaVersion
	if schemaVersion == "" {
		schemaVersion = domain.DefaultSchemaVersion
	}
	schemaID := r.SchemaID
	if schemaID == "" {
		schemaID = domain.DefaultSchemaID
	}
	eventType := r.EventType
	if eventType == "" {
		eventType = "access.lifecycle"
	}
	actorType := r.ActorType
	if actorType == "" {
		actorType = "user"
	}
	subjectType := r.SubjectType
	if subjectType == "" {
		subjectType = "user"
	}
	return domain.Envelope{
		SchemaID:      schemaID,
		SchemaVersion: schemaVersion,
		EventType:     eventType,
		Source:        r.Source,
		CorrelationID: r.CorrelationID,
		TraceID:       r.TraceID,
		TicketID:      r.TicketID,
		Actor: domain.Principal{
			ID:          r.ActorID,
			Type:        actorType,
			DisplayName: r.ActorDisplayName,
		},
		Subject: domain.Principal{
			ID:          r.SubjectID,
			Type:        subjectType,
			DisplayName: r.SubjectDisplayName,
		},
		Resource: domain.Resource{
			System:      r.ResourceSystem,
			Role:        r.ResourceRole,
			Path:        r.ResourcePath,
			Environment: r.ResourceEnv,
			Criticality: r.ResourceCriticality,
		},
		Action:     r.Action,
		Decision:   r.Decision,
		Reason:     r.Reason,
		Timestamp:  time.Now().UTC(),
		Extensions: r.Extensions,
		Fields:     r.Fields,
	}
}

func toEventViews(events []domain.Envelope) []eventView {
	out := make([]eventView, 0, len(events))
	for _, e := range events {
		out = append(out, toEventView(e))
	}
	return out
}

func toEventView(e domain.Envelope) eventView {
	return eventView{
		ID:            e.ID,
		SchemaID:      e.SchemaID,
		SchemaVersion: e.SchemaVersion,
		EventType:     e.EventType,
		Source:        e.Source,
		CorrelationID: e.CorrelationID,
		TraceID:       e.TraceID,
		TicketID:      e.TicketID,
		Actor:         toPrincipalView(e.Actor),
		Subject:       toPrincipalView(e.Subject),
		Resource:      toResourceView(e.Resource),
		Action:        e.Action,
		Decision:      e.Decision,
		Reason:        e.Reason,
		Timestamp:     e.Timestamp,
		ReceivedAt:    e.ReceivedAt,
		Extensions:    e.Extensions,
		Fields:        e.Fields,
		PrevHash:      e.PrevHash,
		Hash:          e.Hash,
	}
}

func toPrincipalView(p domain.Principal) principalView {
	return principalView{ID: p.ID, Type: p.Type, DisplayName: p.DisplayName, Attributes: p.Attributes}
}

func toResourceView(r domain.Resource) resourceView {
	return resourceView{
		System:      r.System,
		Role:        r.Role,
		Path:        r.Path,
		Environment: r.Environment,
		Criticality: r.Criticality,
		Attributes:  r.Attributes,
	}
}

func toAccessLogViews(rows []domain.AccessLogEntry) []accessLogView {
	out := make([]accessLogView, 0, len(rows))
	for _, e := range rows {
		out = append(out, accessLogView{
			ID:        e.ID,
			Timestamp: e.Timestamp,
			Actor:     e.Actor,
			Operation: e.Operation,
			Target:    e.Target,
			Query:     e.Query,
		})
	}
	return out
}
