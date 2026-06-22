package auditcodec

import (
	"encoding/binary"
	"io"
	"time"

	auditv1 "iam-audit/api/proto/iam/audit/v1"
	"iam-audit/internal/domain"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func MarshalEnvelope(e domain.Envelope) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(ToProto(e))
}

func MarshalEnvelopeForHash(e domain.Envelope) ([]byte, error) {
	e.Hash = ""
	return MarshalEnvelope(e)
}

func UnmarshalEnvelope(b []byte) (domain.Envelope, error) {
	msg := &auditv1.AuditEnvelope{}
	if err := proto.Unmarshal(b, msg); err != nil {
		return domain.Envelope{}, err
	}
	return FromProto(msg), nil
}

func WriteDelimited(w io.Writer, payload []byte) error {
	var prefix [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(prefix[:], uint64(len(payload)))
	if _, err := w.Write(prefix[:n]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func ReadDelimited(r io.ByteReader) ([]byte, error) {
	size, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, size)
	for i := range payload {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		payload[i] = b
	}
	return payload, nil
}

func ToProto(e domain.Envelope) *auditv1.AuditEnvelope {
	return &auditv1.AuditEnvelope{
		Id:            e.ID,
		SchemaId:      e.SchemaID,
		SchemaVersion: e.SchemaVersion,
		EventType:     e.EventType,
		Source:        e.Source,
		CorrelationId: e.CorrelationID,
		TraceId:       e.TraceID,
		TicketId:      e.TicketID,
		Actor:         principalToProto(e.Actor),
		Subject:       principalToProto(e.Subject),
		Resource:      resourceToProto(e.Resource),
		Action:        e.Action,
		Decision:      decisionToProto(e.Decision),
		Reason:        e.Reason,
		Timestamp:     timestampToProto(e.Timestamp),
		ReceivedAt:    timestampToProto(e.ReceivedAt),
		Extensions:    cloneMap(e.Extensions),
		Fields:        cloneMap(e.Fields),
		PrevHash:      e.PrevHash,
		Hash:          e.Hash,
		Payload:       cloneBytes(e.Payload),
	}
}

func FromProto(e *auditv1.AuditEnvelope) domain.Envelope {
	if e == nil {
		return domain.Envelope{}
	}
	return domain.Envelope{
		ID:            e.GetId(),
		SchemaID:      e.GetSchemaId(),
		SchemaVersion: e.GetSchemaVersion(),
		EventType:     e.GetEventType(),
		Source:        e.GetSource(),
		CorrelationID: e.GetCorrelationId(),
		TraceID:       e.GetTraceId(),
		TicketID:      e.GetTicketId(),
		Actor:         principalFromProto(e.GetActor()),
		Subject:       principalFromProto(e.GetSubject()),
		Resource:      resourceFromProto(e.GetResource()),
		Action:        e.GetAction(),
		Decision:      decisionFromProto(e.GetDecision()),
		Reason:        e.GetReason(),
		Timestamp:     timestampFromProto(e.GetTimestamp()),
		ReceivedAt:    timestampFromProto(e.GetReceivedAt()),
		Extensions:    cloneMap(e.GetExtensions()),
		Fields:        cloneMap(e.GetFields()),
		PrevHash:      e.GetPrevHash(),
		Hash:          e.GetHash(),
		Payload:       cloneBytes(e.GetPayload()),
	}
}

func principalToProto(p domain.Principal) *auditv1.Principal {
	return &auditv1.Principal{
		Id:          p.ID,
		Type:        p.Type,
		DisplayName: p.DisplayName,
		Attributes:  cloneMap(p.Attributes),
	}
}

func principalFromProto(p *auditv1.Principal) domain.Principal {
	if p == nil {
		return domain.Principal{}
	}
	return domain.Principal{
		ID:          p.GetId(),
		Type:        p.GetType(),
		DisplayName: p.GetDisplayName(),
		Attributes:  cloneMap(p.GetAttributes()),
	}
}

func resourceToProto(r domain.Resource) *auditv1.Resource {
	return &auditv1.Resource{
		System:      r.System,
		Role:        r.Role,
		Path:        r.Path,
		Environment: r.Environment,
		Criticality: r.Criticality,
		Attributes:  cloneMap(r.Attributes),
	}
}

func resourceFromProto(r *auditv1.Resource) domain.Resource {
	if r == nil {
		return domain.Resource{}
	}
	return domain.Resource{
		System:      r.GetSystem(),
		Role:        r.GetRole(),
		Path:        r.GetPath(),
		Environment: r.GetEnvironment(),
		Criticality: r.GetCriticality(),
		Attributes:  cloneMap(r.GetAttributes()),
	}
}

func decisionToProto(v string) auditv1.Decision {
	switch v {
	case "allow":
		return auditv1.Decision_DECISION_ALLOW
	case "deny":
		return auditv1.Decision_DECISION_DENY
	default:
		return auditv1.Decision_DECISION_UNSPECIFIED
	}
}

func decisionFromProto(v auditv1.Decision) string {
	switch v {
	case auditv1.Decision_DECISION_ALLOW:
		return "allow"
	case auditv1.Decision_DECISION_DENY:
		return "deny"
	default:
		return ""
	}
}

func timestampToProto(v time.Time) *timestamppb.Timestamp {
	if v.IsZero() {
		return nil
	}
	return timestamppb.New(v.UTC())
}

func timestampFromProto(v *timestamppb.Timestamp) time.Time {
	if v == nil || !v.IsValid() {
		return time.Time{}
	}
	return v.AsTime()
}

func cloneMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for k, v := range values {
		out[k] = v
	}
	return out
}

func cloneBytes(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out
}
