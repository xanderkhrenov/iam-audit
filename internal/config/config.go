package config

import (
	"os"
	"strings"
)

type Config struct {
	Port                  string
	ClickHouseAddress     string
	ClickHouseDB          string
	ClickHouseUser        string
	ClickHousePass        string
	KafkaEnabled          bool
	KafkaBrokers          []string
	KafkaTopic            string
	KafkaGroupID          string
	SchemaRegistryURL     string
	SchemaRegistryGroupID string
	SchemaRegistryStrict  bool
}

func Load() Config {
	return Config{
		Port:                  getenv("PORT", "8080"),
		ClickHouseAddress:     getenv("CLICKHOUSE_ADDR", "localhost:9000"),
		ClickHouseDB:          getenv("CLICKHOUSE_DB", "iam_audit"),
		ClickHouseUser:        getenv("CLICKHOUSE_USER", "default"),
		ClickHousePass:        getenv("CLICKHOUSE_PASSWORD", ""),
		KafkaEnabled:          getenv("KAFKA_ENABLED", "false") == "true",
		KafkaBrokers:          splitCSV(getenv("KAFKA_BROKERS", "localhost:9092")),
		KafkaTopic:            getenv("KAFKA_TOPIC", "iam.audit.events"),
		KafkaGroupID:          getenv("KAFKA_GROUP_ID", "iam-audit-service"),
		SchemaRegistryURL:     getenv("SCHEMA_REGISTRY_URL", ""),
		SchemaRegistryGroupID: getenv("SCHEMA_REGISTRY_GROUP_ID", "iam-audit"),
		SchemaRegistryStrict:  getenv("SCHEMA_REGISTRY_STRICT", "true") == "true",
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
