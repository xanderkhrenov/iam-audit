# IAM Audit MVP

Прототип централизованной подсистемы аудита и мониторинга для распределенной IAM-платформы.

MVP покрывает базовый контур из требований: прием унифицированных audit envelope-событий, append-only хранение, поиск, корреляцию, отчеты, protobuf-экспорт, журнал обращений и проверку неизменяемости через hash chain.

## Стек

- Backend: Go, `github.com/segmentio/kafka-go` для Kafka ingest/simulator, `github.com/ClickHouse/clickhouse-go/v2` для хранилища.
- Frontend: статический HTML/CSS/JS в отдельной директории `web/`, вшит в Go binary на этапе сборки.
- Хранилище MVP: ClickHouse `MergeTree`; protobuf payload хранится вместе с индексируемыми колонками события.
- Контракт события: protobuf-схемы `api/proto/iam/audit/v1/*.proto` и сгенерированные Go-типы `*.pb.go`.
- Schema Registry: внешний Apicurio Registry в Docker Compose.
- Запуск: Docker / Docker Compose, включая Kafka, ClickHouse и Schema Registry.

События читаются из Kafka или принимаются через HTTP как binary protobuf, а сохраняются в ClickHouse.

## Хранение событий

ClickHouse используется как основное append-only хранилище аудита. Полное событие хранится как protobuf `AuditEnvelope`, а ключевые поля (`actor`, `subject`, `resource_path`, `action`, `decision`, `timestamp`, `correlation_id`, `trace_id`) вынесены в колонки для поиска и агрегаций.

`AuditEnvelope` отвечает за транспортный слой, hash chain, schema id/version, источник события и индексируемые поля. Бизнес-событие IAM хранится внутри envelope в поле `payload` как typed protobuf `IAMAuditEvent`.

Новые поля индексируются без изменения backend-кода через универсальную таблицу:

```text
audit_event_fields(event_id, field_path, field_value, field_type, timestamp)
```

Producer заполняет `payload bytes` typed-сообщением и `fields map<string,string>` поисковыми значениями. Audit-сервис сохраняет весь protobuf envelope и автоматически индексирует все пары `field_path -> field_value`.

Основная payload-схема основана на IAM-модели:

```text
IAMAuditEvent
  id, trace_id, order_id, timestamp, environment, type
  subject: Actor
  admin: Actor
  services: repeated Service
  result: Result -> Role -> repeated Access
```

## Структура проекта

```text
cmd/server/                  # тонкий entrypoint приложения
cmd/simulator/               # Kafka producer для демо-событий
internal/config/             # конфигурация из env
internal/domain/             # доменная модель аудита
internal/httpapi/            # HTTP API и маршруты
internal/ingest/kafka/       # Kafka consumer
internal/proto/auditcodec/   # mapper domain <-> generated protobuf
internal/storage/clickhouse/ # ClickHouse storage
web/static/                  # frontend
api/proto/iam/audit/v1/      # protobuf contracts
internal/schema/             # клиент внешнего Schema Registry
```

## Запуск через Docker

```bash
docker compose up --build
```

Откройте:

```text
http://localhost:8080
```

Если `8080` занят:

```bash
HOST_PORT=8090 docker compose up --build
```

Данные ClickHouse сохраняются в Docker volume `clickhouse-data`.

Kafka поднимается этим же compose-файлом. По умолчанию:

```text
service broker: kafka:9092
host broker: localhost:9094
topic: iam.audit.events
clickhouse native: clickhouse:9000
clickhouse http: localhost:8123
schema registry: http://localhost:8081
```

Compose также поднимает Apicurio Registry и init-контейнер, который регистрирует protobuf artifact:

```text
group_id: iam-audit
schema_id / artifact_id: iam.access.lifecycle
schema_version: 1
schema file: api/proto/iam/audit/v1/access_lifecycle.proto
```

Backend перед сохранением события проверяет, что `schema_id + schema_version` существуют в Schema Registry. Неизвестная схема отклоняется.

Симулировать отправку IAM-событий через Kafka:

```bash
docker compose --profile tools run --rm kafka-simulator
```

После этого события будут прочитаны backend consumer'ом и появятся в веб-интерфейсе и API.

## Добавление событий через админку

1. Запустите проект через Docker.
2. Откройте `http://localhost:8080`.
3. В блоке `Админка событий` заполните поля события.
4. В textarea `fields` добавьте новые поисковые поля в формате `path=value`, по одному на строку:

```text
approval.policy=manual-admin
approval.risk_score=45
access.expires_at=2026-12-31T00:00:00Z
event.order_id=10001
service.id=erp
service.name=ERP
result.role_id=auditor
```

5. Нажмите `Создать событие`.

Событие будет сохранено в ClickHouse как protobuf `AuditEnvelope` с вложенным typed payload `IAMAuditEvent`. Все значения из `fields` автоматически попадут в индекс `audit_event_fields`, поэтому по ним сразу можно искать через UI или API:

```bash
curl "http://localhost:8080/api/events?field=approval.policy&field_value=manual-admin"
```

Остановить сервис:

```bash
docker compose down
```

Остановить и удалить данные:

```bash
docker compose down -v
```

## Локальный dev-запуск

Если Docker не нужен:

```bash
go run ./cmd/server
```

Для другого порта локально:

```bash
PORT=8090 go run ./cmd/server
```

Локально включить Kafka consumer:

```bash
KAFKA_ENABLED=true KAFKA_BROKERS=localhost:9094 go run ./cmd/server
```

Локально отправить демо-события в Kafka:

```bash
KAFKA_BROKERS=localhost:9094 go run ./cmd/simulator
```

## Быстрая проверка API

Загрузить демо-события:

```bash
curl -X POST http://localhost:8080/api/seed
```

Альтернатива через Kafka:

```bash
docker compose --profile tools run --rm kafka-simulator
```

Поиск:

```bash
curl "http://localhost:8080/api/events?actor=manager&system=erp"
```

Поиск по новым полям:

```bash
curl "http://localhost:8080/api/events?field=approval.risk_score&field_value=70"
curl "http://localhost:8080/api/events?q=owner-approval"
```

Корреляция цепочки заявки:

```bash
curl http://localhost:8080/api/correlations/REQ-1001
```

Отчет по выданным ролям:

```bash
curl http://localhost:8080/api/reports/roles-by-system
```

Проверка hash chain:

```bash
curl http://localhost:8080/api/integrity
```

Экспорт для SIEM:

```bash
curl "http://localhost:8080/api/exports/siem?system=erp"
```

## Основные endpoint'ы

- `POST /api/events` - принять IAM audit envelope в `application/x-protobuf`.
- `POST /api/admin/events` - создать событие из админки; backend сохраняет его как protobuf envelope.
- `GET /api/events` - поиск и фильтрация по ключевым и вложенным полям.
- `GET /api/correlations/{id}` - цепочка событий по `correlation_id`, `trace_id` или `ticket_id`.
- `GET /api/reports/roles-by-system` - сколько ролей выдано по системам.
- `GET /api/reports/critical-approvals` - кто согласовал критические доступы.
- `GET /api/reports/auto-revocations` - автоматически отозванные роли.
- `GET /api/reports/expirations` - истекшие и продленные доступы.
- `GET /api/exports/siem` - выгрузка событий в length-delimited protobuf.
- `GET /api/access-log` - журнал обращений к поиску, отчетам и экспорту.
- `GET /api/integrity` - проверка hash chain.

## Protobuf schema registry

Контракт envelope хранится в `api/proto/iam/audit/v1/envelope.proto`.
Контракт IAM payload хранится в `api/proto/iam/audit/v1/access_lifecycle.proto`.
Go-типы генерируются в `api/proto/iam/audit/v1/*.pb.go`; ручная protobuf-сериализация не используется.

Перегенерировать protobuf-код:

```bash
PATH="$HOME/go/bin:$PATH" protoc --go_out=. --go_opt=module=iam-audit \
  api/proto/iam/audit/v1/envelope.proto \
  api/proto/iam/audit/v1/access_lifecycle.proto
```

Kafka, HTTP ingest/export, append-only storage и hash chain работают с binary protobuf. JSON используется только для HTTP-представления веб-интерфейса и команд админки.

Внешний Schema Registry доступен по `http://localhost:8081`. Проверить зарегистрированную схему:

```bash
curl http://localhost:8081/apis/registry/v2/groups/iam-audit/artifacts/iam.access.lifecycle/versions/1
```

Новые типы событий добавляются так:

1. Добавить `.proto` payload-схему, например `api/proto/iam/audit/v1/access_lifecycle.proto`.
2. Зарегистрировать ее в Apicurio Registry как новый artifact/version.
3. Producer заполняет стабильный envelope, указывает `schema_id` и `schema_version`, а новые поисковые поля кладет в `fields`.
4. Audit-сервис проверяет схему во внешнем registry, пишет событие в ClickHouse и индексирует `fields` в `audit_event_fields`.
