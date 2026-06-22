package domain

import (
	"strings"
	"time"
)

func SampleEvents() []Envelope {
	return []Envelope{
		sample("REQ-1001", "approve_access", "allow", "iam-workflow", "manager-17", "Ирина Петрова", "user-42", "Алексей Иванов", "erp", "finance-admin", "/erp/roles/finance-admin", "prod", "critical", "approved by owner"),
		sample("REQ-1001", "grant_role", "allow", "iam-provisioner", "svc-iam", "IAM Provisioner", "user-42", "Алексей Иванов", "erp", "finance-admin", "/erp/roles/finance-admin", "prod", "critical", "provisioned"),
		sample("REQ-1002", "grant_role", "deny", "iam-policy", "svc-policy", "Policy Engine", "user-77", "Мария Смирнова", "crm", "sales-export", "/crm/roles/sales-export", "prod", "high", "SoD violation"),
		sample("REQ-1003", "revoke_role", "allow", "iam-scheduler", "svc-scheduler", "Scheduler", "user-42", "Алексей Иванов", "erp", "finance-admin", "/erp/roles/finance-admin", "prod", "critical", "automatic expiration"),
		sample("REQ-1004", "extend_access", "allow", "iam-workflow", "manager-21", "Олег Соколов", "user-88", "Наталья Орлова", "bi", "analyst", "/bi/roles/analyst", "stage", "medium", "extension approved"),
		sample("REQ-1005", "expire_access", "allow", "iam-scheduler", "svc-scheduler", "Scheduler", "user-90", "Павел Морозов", "gitlab", "maintainer", "/gitlab/groups/platform/maintainer", "prod", "high", "expired by ttl"),
	}
}

func sample(ticket, action, decision, source, actorID, actorName, subjectID, subjectName, system, role, path, env, criticality, reason string) Envelope {
	now := time.Now().UTC()
	expiresAt := now.Add(90 * 24 * time.Hour).Format(time.RFC3339)
	orderID := strings.TrimPrefix(ticket, "REQ-")
	return Envelope{
		SchemaVersion: DefaultSchemaVersion,
		SchemaID:      DefaultSchemaID,
		EventType:     "access.lifecycle",
		Source:        source,
		CorrelationID: ticket,
		TraceID:       "trace-" + strings.TrimPrefix(ticket, "REQ-"),
		TicketID:      ticket,
		Actor: Principal{ID: actorID, Type: "user", DisplayName: actorName, Attributes: map[string]string{
			"email":      actorID + "@example.local",
			"platform":   "web",
			"ip":         "10.0.0.10",
			"user_agent": "iam-demo",
		}},
		Subject: Principal{ID: subjectID, Type: "user", DisplayName: subjectName, Attributes: map[string]string{
			"email":    subjectID + "@example.local",
			"platform": "web",
		}},
		Resource: Resource{
			System: system, Role: role, Path: path, Environment: env, Criticality: criticality,
			Attributes: map[string]string{
				"service_id": system,
				"access_id":  path,
			},
		},
		Action:     action,
		Decision:   decision,
		Reason:     reason,
		Timestamp:  now.Add(-time.Duration(len(ticket)+len(action)) * time.Hour),
		Extensions: map[string]string{"rbac_model": "role-based", "source_contract": "protobuf"},
		Fields: map[string]string{
			"request.ticket_id":      ticket,
			"access.system":          system,
			"access.role":            role,
			"access.environment":     env,
			"access.criticality":     criticality,
			"approval.business_unit": "security",
			"approval.risk_score":    "70",
			"approval.policy":        "owner-approval",
			"access.expires_at":      expiresAt,
			"event.order_id":         orderID,
			"event.type":             action,
			"service.id":             system,
			"service.name":           system,
			"result.role_id":         role,
			"result.comment":         reason,
			"admin.id":               actorID,
			"subject.metadata.email": subjectID + "@example.local",
			"admin.metadata.email":   actorID + "@example.local",
		},
	}
}
