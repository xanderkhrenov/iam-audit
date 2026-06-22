package main

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"

	"iam-audit/internal/domain"
	"iam-audit/internal/proto/auditcodec"
)

func main() {
	brokers := splitCSV(getenv("KAFKA_BROKERS", "localhost:9092"))
	topic := getenv("KAFKA_TOPIC", "iam.audit.events")

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers:      brokers,
		Topic:        topic,
		RequiredAcks: int(kafka.RequireOne),
		Async:        false,
	})
	defer writer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, event := range domain.SampleEvents() {
		payload, err := auditcodec.MarshalEnvelope(event)
		if err != nil {
			log.Fatal(err)
		}
		msg := kafka.Message{
			Key:   []byte(event.CorrelationID),
			Value: payload,
			Time:  time.Now().UTC(),
		}
		if err := writer.WriteMessages(ctx, msg); err != nil {
			log.Fatalf("publish to Kafka failed: %v", err)
		}
		log.Printf("published event: ticket=%s action=%s subject=%s", event.TicketID, event.Action, event.Subject.ID)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
