package kafka

import (
	"context"
	"log"
	"time"

	"github.com/segmentio/kafka-go"

	"iam-audit/internal/domain"
	"iam-audit/internal/proto/auditcodec"
)

type Store interface {
	AppendEvent(*domain.Envelope) error
}

type Config struct {
	Brokers []string
	Topic   string
	GroupID string
}

type Consumer struct {
	cfg   Config
	store Store
}

func NewConsumer(cfg Config, store Store) *Consumer {
	return &Consumer{cfg: cfg, store: store}
}

func (c *Consumer) Run(ctx context.Context) {
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        c.cfg.Brokers,
		Topic:          c.cfg.Topic,
		GroupID:        c.cfg.GroupID,
		MinBytes:       1,
		MaxBytes:       10e6,
		CommitInterval: time.Second,
		StartOffset:    kafka.FirstOffset,
	})
	defer reader.Close()

	log.Printf("Kafka consumer started: brokers=%v topic=%s group=%s", c.cfg.Brokers, c.cfg.Topic, c.cfg.GroupID)
	for {
		msg, err := reader.ReadMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("Kafka read error: %v", err)
			continue
		}

		event, err := auditcodec.UnmarshalEnvelope(msg.Value)
		if err != nil {
			log.Printf("Kafka invalid protobuf event: topic=%s partition=%d offset=%d error=%v", msg.Topic, msg.Partition, msg.Offset, err)
			continue
		}
		if err := c.store.AppendEvent(&event); err != nil {
			log.Printf("Kafka append event failed: topic=%s partition=%d offset=%d error=%v", msg.Topic, msg.Partition, msg.Offset, err)
			continue
		}
		log.Printf("Kafka event ingested: topic=%s partition=%d offset=%d action=%s subject=%s", msg.Topic, msg.Partition, msg.Offset, event.Action, event.Subject.ID)
	}
}
