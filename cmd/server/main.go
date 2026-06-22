package main

import (
	"context"
	"log"
	"net/http"
	"os/signal"
	"syscall"

	"iam-audit/internal/config"
	"iam-audit/internal/httpapi"
	kafkaingest "iam-audit/internal/ingest/kafka"
	"iam-audit/internal/schema"
	"iam-audit/internal/storage/clickhouse"
	"iam-audit/web"
)

func main() {
	cfg := config.Load()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := clickhouse.NewStore(ctx, clickhouse.Config{
		Address:  cfg.ClickHouseAddress,
		Database: cfg.ClickHouseDB,
		Username: cfg.ClickHouseUser,
		Password: cfg.ClickHousePass,
		SchemaValidator: schema.NewRegistry(schema.Config{
			URL:     cfg.SchemaRegistryURL,
			GroupID: cfg.SchemaRegistryGroupID,
			Strict:  cfg.SchemaRegistryStrict,
		}),
	})
	if err != nil {
		log.Fatal(err)
	}

	if cfg.KafkaEnabled {
		consumer := kafkaingest.NewConsumer(kafkaingest.Config{
			Brokers: cfg.KafkaBrokers,
			Topic:   cfg.KafkaTopic,
			GroupID: cfg.KafkaGroupID,
		}, store)
		go consumer.Run(ctx)
	}

	router := httpapi.NewRouter(store, web.StaticFS())
	log.Printf("IAM Audit MVP started: http://localhost:%s", cfg.Port)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, httpapi.LogRequest(router)))
}
