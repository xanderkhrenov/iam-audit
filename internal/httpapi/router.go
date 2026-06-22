package httpapi

import (
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"iam-audit/internal/domain"
	"iam-audit/internal/proto/auditcodec"
)

type Store interface {
	EventCount() int
	AppendEvent(*domain.Envelope) error
	Search(domain.Filter) []domain.Envelope
	Correlation(string) []domain.Envelope
	VerifyHashChain() (bool, string)
	Seed() error
	AccessLog() []domain.AccessLogEntry
	LogAccess(domain.AccessLogEntry)
}

type Handler struct {
	store Store
	webFS fs.FS
}

func NewRouter(store Store, webFS fs.FS) http.Handler {
	h := &Handler{store: store, webFS: webFS}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("POST /api/events", h.createEvent)
	mux.HandleFunc("POST /api/admin/events", h.createAdminEvent)
	mux.HandleFunc("GET /api/events", h.searchEvents)
	mux.HandleFunc("GET /api/correlations/{id}", h.correlation)
	mux.HandleFunc("GET /api/reports/roles-by-system", h.rolesBySystem)
	mux.HandleFunc("GET /api/reports/critical-approvals", h.criticalApprovals)
	mux.HandleFunc("GET /api/reports/auto-revocations", h.autoRevocations)
	mux.HandleFunc("GET /api/reports/expirations", h.expirations)
	mux.HandleFunc("GET /api/exports/siem", h.siemExport)
	mux.HandleFunc("GET /api/access-log", h.accessLog)
	mux.HandleFunc("GET /api/integrity", h.integrity)
	mux.HandleFunc("POST /api/seed", h.seed)
	mux.HandleFunc("GET /", h.index)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(webFS))))
	return mux
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "events": h.store.EventCount()})
}

func (h *Handler) createEvent(w http.ResponseWriter, r *http.Request) {
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "cannot read request body")
		return
	}
	e, err := auditcodec.UnmarshalEnvelope(payload)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid protobuf")
		return
	}
	if err := h.store.AppendEvent(&e); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, toEventView(e))
}

func (h *Handler) createAdminEvent(w http.ResponseWriter, r *http.Request) {
	var req adminEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid admin event request")
		return
	}
	e := req.toEnvelope()
	if err := h.store.AppendEvent(&e); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "admin-create", "event:"+e.ID)
	writeJSON(w, http.StatusCreated, toEventView(e))
}

func (h *Handler) searchEvents(w http.ResponseWriter, r *http.Request) {
	h.audit(r, "search", "events")
	events := h.store.Search(parseFilter(r))
	writeJSON(w, http.StatusOK, map[string]any{"items": toEventViews(events), "total": len(events)})
}

func (h *Handler) correlation(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	h.audit(r, "trace", "correlation:"+id)
	events := h.store.Correlation(id)
	sort.Slice(events, func(i, j int) bool { return events[i].Timestamp.Before(events[j].Timestamp) })
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "items": toEventViews(events), "total": len(events)})
}

func (h *Handler) rolesBySystem(w http.ResponseWriter, r *http.Request) {
	h.audit(r, "report", "roles-by-system")
	type key struct{ System, Role string }
	counts := map[key]int{}
	for _, e := range h.store.Search(parseFilter(r)) {
		if e.Action == "grant_role" && e.Decision == "allow" {
			counts[key{e.Resource.System, e.Resource.Role}]++
		}
	}
	rows := []map[string]any{}
	for k, v := range counts {
		rows = append(rows, map[string]any{"system": k.System, "role": k.Role, "count": v})
	}
	writeJSON(w, http.StatusOK, rows)
}

func (h *Handler) criticalApprovals(w http.ResponseWriter, r *http.Request) {
	h.audit(r, "report", "critical-approvals")
	rows := []domain.Envelope{}
	for _, e := range h.store.Search(parseFilter(r)) {
		if e.Action == "approve_access" && strings.EqualFold(e.Resource.Criticality, "critical") {
			rows = append(rows, e)
		}
	}
	writeJSON(w, http.StatusOK, toEventViews(rows))
}

func (h *Handler) autoRevocations(w http.ResponseWriter, r *http.Request) {
	h.audit(r, "report", "auto-revocations")
	rows := []domain.Envelope{}
	for _, e := range h.store.Search(parseFilter(r)) {
		if e.Action == "revoke_role" && strings.Contains(strings.ToLower(e.Reason), "auto") {
			rows = append(rows, e)
		}
	}
	writeJSON(w, http.StatusOK, toEventViews(rows))
}

func (h *Handler) expirations(w http.ResponseWriter, r *http.Request) {
	h.audit(r, "report", "expirations")
	rows := []domain.Envelope{}
	for _, e := range h.store.Search(parseFilter(r)) {
		if e.Action == "expire_access" || e.Action == "extend_access" {
			rows = append(rows, e)
		}
	}
	writeJSON(w, http.StatusOK, toEventViews(rows))
}

func (h *Handler) siemExport(w http.ResponseWriter, r *http.Request) {
	h.audit(r, "export", "siem")
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.Header().Set("Content-Disposition", `attachment; filename="iam-audit-export.pb"`)
	for _, e := range h.store.Search(parseFilter(r)) {
		payload, err := auditcodec.MarshalEnvelope(e)
		if err != nil {
			continue
		}
		_ = auditcodec.WriteDelimited(w, payload)
	}
}

func (h *Handler) accessLog(w http.ResponseWriter, _ *http.Request) {
	rows := h.store.AccessLog()
	writeJSON(w, http.StatusOK, map[string]any{"items": toAccessLogViews(rows), "total": len(rows)})
}

func (h *Handler) integrity(w http.ResponseWriter, r *http.Request) {
	h.audit(r, "verify", "hash-chain")
	ok, brokenAt := h.store.VerifyHashChain()
	writeJSON(w, http.StatusOK, map[string]any{"ok": ok, "events": h.store.EventCount(), "broken_at": brokenAt})
}

func (h *Handler) seed(w http.ResponseWriter, _ *http.Request) {
	if err := h.store.Seed(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "seeded", "events": h.store.EventCount()})
}

func (h *Handler) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFileFS(w, r, h.webFS, "index.html")
}

func (h *Handler) audit(r *http.Request, op, target string) {
	actor := r.Header.Get("X-Audit-Actor")
	if actor == "" {
		actor = "local-user"
	}
	h.store.LogAccess(domain.AccessLogEntry{
		ID:        newID(),
		Timestamp: time.Now().UTC(),
		Actor:     actor,
		Operation: op,
		Target:    target,
		Query:     r.URL.RawQuery,
	})
}

func parseFilter(r *http.Request) domain.Filter {
	q := r.URL.Query()
	f := domain.Filter{
		Query:         q.Get("q"),
		Actor:         q.Get("actor"),
		Subject:       q.Get("subject"),
		ResourcePath:  q.Get("resource_path"),
		Action:        q.Get("action"),
		Decision:      q.Get("decision"),
		System:        q.Get("system"),
		Environment:   q.Get("environment"),
		CorrelationID: q.Get("correlation_id"),
		TraceID:       q.Get("trace_id"),
		TicketID:      q.Get("ticket_id"),
		FieldPath:     q.Get("field"),
		FieldValue:    q.Get("field_value"),
	}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.Offset, _ = strconv.Atoi(q.Get("offset"))
	f.From = parseTime(q.Get("from"))
	f.To = parseTime(q.Get("to"))
	return f
}

func parseTime(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t
	}
	return time.Time{}
}

func newID() string {
	return strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func LogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		next.ServeHTTP(w, r)
	})
}
