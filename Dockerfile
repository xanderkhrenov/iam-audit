FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY go.sum* ./
COPY api ./api
COPY cmd ./cmd
COPY internal ./internal
COPY web ./web
RUN go build -o /out/iam-audit ./cmd/server
RUN go build -o /out/iam-audit-simulator ./cmd/simulator

FROM alpine:3.22
WORKDIR /app
ENV PORT=8080
COPY --from=build /out/iam-audit /app/iam-audit
COPY --from=build /out/iam-audit-simulator /app/iam-audit-simulator
EXPOSE 8080
ENTRYPOINT ["/app/iam-audit"]
