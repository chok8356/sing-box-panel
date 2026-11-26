package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"maps"
	"net/http"
	"sync"
	"time"

	"sing-box-panel/internal/singbox"
	"sing-box-panel/internal/singbox/connectionapi"
)

type onlineClients map[string]int // Active connections by subscription UUID. Nil means unavailable.

func (online onlineClients) status(enabled bool, uuid string) string {
	switch {
	case !enabled:
		return "—"
	case online == nil:
		return "Unavailable"
	case online[uuid] > 0:
		return "Online"
	default:
		return "Offline"
	}
}

type clientPresence struct {
	mu     sync.Mutex
	run    <-chan struct{}
	online onlineClients
}

func (a *app) onlineClients() onlineClients {
	if !a.mu.TryRLock() {
		return nil
	}
	defer a.mu.RUnlock()
	a.presence.mu.Lock()
	defer a.presence.mu.Unlock()
	if a.core == nil || !a.core.Running() || a.presence.run != a.core.Done() {
		return nil
	}
	return maps.Clone(a.presence.online)
}

type presenceSession struct {
	inbounds    map[string]string
	names       map[string]string
	naiveUsers  map[string]string
	connections map[string]string // Connection ID to subscription UUID.
}

func (a *app) presenceSession(ctx context.Context) (<-chan struct{}, *presenceSession, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.core.Running() {
		return nil, nil, nil
	}
	inbounds, err := singbox.ManagedInbounds(a.core.Current())
	if err != nil {
		return nil, nil, err
	}
	session := &presenceSession{
		inbounds: inbounds, names: make(map[string]string), naiveUsers: make(map[string]string),
		connections: make(map[string]string),
	}
	rows, err := a.db.QueryContext(ctx, "SELECT name, uuid FROM subscriptions WHERE enabled = 1")
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name, uuid string
		if err := rows.Scan(&name, &uuid); err != nil {
			return nil, nil, err
		}
		session.names[name] = uuid
		session.naiveUsers[uuid] = uuid
	}
	return a.core.Done(), session, rows.Err()
}

func (s *presenceSession) apply(batch *connectionapi.ConnectionEvents, online onlineClients, pending map[string]int64, now time.Time) onlineClients {
	if batch.GetReset_() {
		clear(s.connections)
		online = make(onlineClients)
	}
	if online == nil {
		return nil
	}
	for _, event := range batch.Events {
		if event.GetId() == "" || (event.Type != connectionapi.ConnectionEventType_CONNECTION_EVENT_NEW &&
			event.Type != connectionapi.ConnectionEventType_CONNECTION_EVENT_CLOSED) {
			continue
		}
		uuid := s.connections[event.Id]
		connection := event.GetConnection()
		if uuid == "" && connection != nil && connection.User != "" {
			inboundType, managed := s.inbounds[connection.Inbound]
			if !managed || inboundType != connection.InboundType {
				continue
			}
			uuid = s.names[connection.User]
			if inboundType == "naive" {
				uuid = s.naiveUsers[connection.User]
			}
		}
		if uuid == "" {
			continue
		}
		closedAt := max(event.ClosedAt, connection.GetClosedAt())
		if closedAt > 0 || event.Type == connectionapi.ConnectionEventType_CONNECTION_EVENT_CLOSED {
			seen := now.Unix()
			if closedAt > 0 {
				seen = time.UnixMilli(closedAt).Unix()
			}
			pending[uuid] = max(pending[uuid], seen)
			if _, active := s.connections[event.Id]; active {
				delete(s.connections, event.Id)
				online[uuid]--
				if online[uuid] == 0 {
					delete(online, uuid)
				}
			}
		} else if _, active := s.connections[event.Id]; !active {
			s.connections[event.Id] = uuid
			online[uuid]++
			pending[uuid] = max(pending[uuid], now.Unix())
		}
	}
	return online
}

func (a *app) watchPresence(ctx context.Context) {
	pending := make(map[string]int64)
	retry := time.NewTicker(time.Second)
	defer retry.Stop()
	for ctx.Err() == nil {
		run, session, err := a.presenceSession(ctx)
		if err != nil && ctx.Err() == nil {
			log.Printf("cannot read clients for activity tracking: %v", err)
		}
		if err == nil && session != nil {
			a.trackPresence(ctx, run, session, pending)
		}
		a.flushLastSeen(context.WithoutCancel(ctx), pending)
		select {
		case <-ctx.Done():
			return
		case <-retry.C:
		}
	}
}

func (a *app) trackPresence(ctx context.Context, run <-chan struct{}, session *presenceSession, pending map[string]int64) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	batches := make(chan *connectionapi.ConnectionEvents)
	go func() {
		defer close(batches)
		_ = a.connectionAPI.Subscribe(ctx, func(batch *connectionapi.ConnectionEvents) bool {
			select {
			case batches <- batch:
				return true
			case <-ctx.Done():
				return false
			}
		})
	}()
	defer func() {
		a.presence.mu.Lock()
		a.presence.run, a.presence.online = nil, nil
		a.presence.mu.Unlock()
	}()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	var online onlineClients
	for {
		select {
		case <-ctx.Done():
			return
		case <-run:
			return
		case batch, ok := <-batches:
			if !ok {
				return
			}
			a.presence.mu.Lock()
			online = session.apply(batch, online, pending, time.Now())
			a.presence.run, a.presence.online = run, online
			a.presence.mu.Unlock()
		case now := <-tick.C:
			for uuid := range online {
				pending[uuid] = max(pending[uuid], now.Unix())
			}
			a.flushLastSeen(ctx, pending)
		}
	}
}

func (a *app) flushLastSeen(ctx context.Context, pending map[string]int64) {
	if len(pending) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := a.storeLastSeen(ctx, pending); err != nil {
		if ctx.Err() == nil {
			log.Printf("cannot save client activity: %v", err)
		}
		return
	}
	clear(pending)
}

func (a *app) storeLastSeen(ctx context.Context, pending map[string]int64) error {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for uuid, seen := range pending {
		if _, err := tx.ExecContext(ctx, `UPDATE subscriptions SET last_seen_at = ?
			WHERE uuid = ? AND created_at <= ? AND (last_seen_at IS NULL OR last_seen_at < ?)`,
			seen, uuid, seen, seen); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func formatClientDate(timestamp int64) string {
	return time.Unix(timestamp, 0).UTC().Format("2006-01-02 15:04 UTC")
}

func (a *app) subscriptionActivity(w http.ResponseWriter, r *http.Request) {
	online := a.onlineClients()
	rows, err := a.db.QueryContext(r.Context(), "SELECT id, enabled, uuid, last_seen_at FROM subscriptions")
	if err != nil {
		serverError(w)
		return
	}
	defer rows.Close()
	type activity struct {
		Status   string `json:"status"`
		LastSeen string `json:"lastSeen"`
	}
	clients := make(map[int64]activity)
	for rows.Next() {
		var id int64
		var enabled bool
		var uuid string
		var lastSeen sql.NullInt64
		if err := rows.Scan(&id, &enabled, &uuid, &lastSeen); err != nil {
			serverError(w)
			return
		}
		client := activity{Status: online.status(enabled, uuid), LastSeen: "—"}
		if lastSeen.Valid {
			client.LastSeen = formatClientDate(lastSeen.Int64)
		}
		clients[id] = client
	}
	if rows.Err() != nil {
		serverError(w)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(clients)
}
