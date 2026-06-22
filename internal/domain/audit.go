package domain

import "time"

const (
	DefaultSchemaID      = "iam.access.lifecycle"
	DefaultSchemaVersion = "1"
)

type Envelope struct {
	ID            string
	SchemaID      string
	SchemaVersion string
	EventType     string
	Source        string
	CorrelationID string
	TraceID       string
	TicketID      string
	Actor         Principal
	Subject       Principal
	Resource      Resource
	Action        string
	Decision      string
	Reason        string
	Timestamp     time.Time
	ReceivedAt    time.Time
	Extensions    map[string]string
	Fields        map[string]string
	PrevHash      string
	Hash          string
	Payload       []byte
}

type Principal struct {
	ID          string
	Type        string
	DisplayName string
	Attributes  map[string]string
}

type Resource struct {
	System      string
	Role        string
	Path        string
	Environment string
	Criticality string
	Attributes  map[string]string
}

type Filter struct {
	Query, Actor, Subject, ResourcePath, Action, Decision, System, Environment string
	CorrelationID, TraceID, TicketID                                           string
	FieldPath, FieldValue                                                      string
	From, To                                                                   time.Time
	Limit, Offset                                                              int
}

type AccessLogEntry struct {
	ID        string
	Timestamp time.Time
	Actor     string
	Operation string
	Target    string
	Query     string
}
