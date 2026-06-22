package auditcodec

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	auditv1 "iam-audit/api/proto/iam/audit/v1"
	"iam-audit/internal/domain"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func EnsureAccessLifecyclePayload(e *domain.Envelope) error {
	if e == nil || len(e.Payload) > 0 || e.SchemaID != domain.DefaultSchemaID {
		return nil
	}
	payload := AccessLifecyclePayload(*e)
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(payload)
	if err != nil {
		return err
	}
	e.Payload = b
	return nil
}

func AccessLifecyclePayload(e domain.Envelope) *auditv1.IAMAuditEvent {
	return &auditv1.IAMAuditEvent{
		Id:             firstNonEmpty(e.ID, e.TicketID),
		TraceId:        e.TraceID,
		OrderId:        orderID(e),
		Timestamp:      timestampToProto(e.Timestamp),
		Environment:    e.Resource.Environment,
		Type:           e.Action,
		Subject:        iamActor(e.Subject),
		Services:       []*auditv1.Service{iamService(e)},
		RequestComment: e.Reason,
		Admin:          iamActor(e.Actor),
		Result: &auditv1.Result{
			Decision: e.Decision,
			Role: &auditv1.Role{
				Id:       firstNonEmpty(e.Resource.Role, e.Resource.Path),
				Accesses: []*auditv1.Access{iamAccess(e)},
			},
			Comment: e.Reason,
		},
	}
}

func iamActor(p domain.Principal) *auditv1.Actor {
	return &auditv1.Actor{
		Id: p.ID,
		Metadata: &auditv1.Metadata{
			Ip:        p.Attributes["ip"],
			Platform:  p.Attributes["platform"],
			UserAgent: p.Attributes["user_agent"],
			DeviceId:  p.Attributes["device_id"],
			Email:     p.Attributes["email"],
		},
	}
}

func iamService(e domain.Envelope) *auditv1.Service {
	return &auditv1.Service{
		Id:     firstNonEmpty(e.Resource.Attributes["service_id"], e.Resource.System),
		Name:   e.Resource.System,
		Owners: []*auditv1.Actor{iamActor(e.Actor)},
		Metadata: &auditv1.Metadata{
			Platform: e.Resource.Environment,
		},
	}
}

func iamAccess(e domain.Envelope) *auditv1.Access {
	return &auditv1.Access{
		Id:      firstNonEmpty(e.Resource.Attributes["access_id"], e.Resource.Path),
		Service: iamService(e),
		Since:   timestampToProto(e.Timestamp),
		Till:    parseTimestamp(e.Fields["access.expires_at"]),
	}
}

func orderID(e domain.Envelope) int64 {
	for _, value := range []string{e.Fields["event.order_id"], e.Extensions["order_id"]} {
		if value == "" {
			continue
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err == nil {
			return n
		}
	}
	if e.Timestamp.IsZero() {
		return time.Now().UnixNano()
	}
	return e.Timestamp.UnixNano()
}

func parseTimestamp(value string) *timestamppb.Timestamp {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil
	}
	return timestamppb.New(t.UTC())
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
