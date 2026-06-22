package auditcodec

import (
	"testing"

	"iam-audit/internal/domain"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	event := domain.SampleEvents()[0]
	if err := EnsureAccessLifecyclePayload(&event); err != nil {
		t.Fatal(err)
	}
	payload, err := MarshalEnvelope(event)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalEnvelope(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got.TicketID != event.TicketID || got.Actor.ID != event.Actor.ID || got.Resource.Path != event.Resource.Path {
		t.Fatalf("unexpected roundtrip: %#v", got)
	}
	if len(got.Payload) == 0 {
		t.Fatal("payload was not preserved")
	}
}
