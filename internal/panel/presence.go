package panel

import (
	"context"
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
	mu      sync.Mutex
	run     <-chan struct{}
	online  onlineClients
	pending map[string]pendingActivity
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
	connections map[string]trackedConnection
}

type trackedConnection struct {
	uuid             string
	upload, download int64 // Initial baseline plus the deltas already counted.
}

type pendingActivity struct {
	seen             int64
	upload, download int64
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
		connections: make(map[string]trackedConnection),
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

func (s *presenceSession) apply(batch *connectionapi.ConnectionEvents, online onlineClients, pending map[string]pendingActivity, now time.Time) onlineClients {
	if batch.GetReset_() {
		clear(s.connections)
		online = make(onlineClients)
	}
	if online == nil {
		return nil
	}
	for _, event := range batch.Events {
		if event.GetId() == "" {
			continue
		}
		tracked, active := s.connections[event.Id]
		if event.Type == connectionapi.ConnectionEventType_CONNECTION_EVENT_UPDATE {
			upload, download := max(0, event.UplinkDelta), max(0, event.DownlinkDelta)
			if active && (upload > 0 || download > 0) {
				update := pending[tracked.uuid]
				update.seen = max(update.seen, now.Unix())
				update.upload += upload
				update.download += download
				pending[tracked.uuid] = update
				tracked.upload += upload
				tracked.download += download
				s.connections[event.Id] = tracked
			}
			continue
		}
		if event.Type != connectionapi.ConnectionEventType_CONNECTION_EVENT_NEW &&
			event.Type != connectionapi.ConnectionEventType_CONNECTION_EVENT_CLOSED {
			continue
		}
		uuid := tracked.uuid
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
			update := pending[uuid]
			update.seen = max(update.seen, seen)
			if active {
				// Include bytes between the last update and close. The initial
				// snapshot may also replay closed connections we already counted.
				update.upload += max(0, connection.GetUplinkTotal()-tracked.upload)
				update.download += max(0, connection.GetDownlinkTotal()-tracked.download)
				delete(s.connections, event.Id)
				online[uuid]--
				if online[uuid] == 0 {
					delete(online, uuid)
				}
			}
			pending[uuid] = update
		} else if !active {
			tracked.uuid = uuid
			if batch.GetReset_() {
				// A new stream can include bytes from before this subscription
				// to the events API. Use them as a baseline, never as new usage.
				tracked.upload = connection.GetUplinkTotal()
				tracked.download = connection.GetDownlinkTotal()
			}
			s.connections[event.Id] = tracked
			online[uuid]++
			update := pending[uuid]
			update.seen = max(update.seen, now.Unix())
			pending[uuid] = update
		}
	}
	return online
}

func (a *app) watchPresence(ctx context.Context) {
	a.presence.mu.Lock()
	a.presence.pending = make(map[string]pendingActivity)
	a.presence.mu.Unlock()
	defer func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.writeActivity(context.WithoutCancel(ctx))
	}()
	retry := time.NewTicker(time.Second)
	defer retry.Stop()
	for ctx.Err() == nil {
		run, session, err := a.presenceSession(ctx)
		if err != nil && ctx.Err() == nil {
			log.Printf("cannot read clients for activity tracking: %v", err)
		}
		if err == nil && session != nil {
			a.trackPresence(ctx, run, session)
		}
		a.flushActivity(context.WithoutCancel(ctx))
		select {
		case <-ctx.Done():
			return
		case <-retry.C:
		}
	}
}

func (a *app) trackPresence(ctx context.Context, run <-chan struct{}, session *presenceSession) {
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
			online = session.apply(batch, online, a.presence.pending, time.Now())
			a.presence.run, a.presence.online = run, online
			a.presence.mu.Unlock()
		case now := <-tick.C:
			a.presence.mu.Lock()
			for uuid := range online {
				update := a.presence.pending[uuid]
				update.seen = max(update.seen, now.Unix())
				a.presence.pending[uuid] = update
			}
			a.presence.mu.Unlock()
			a.flushActivity(ctx)
		}
	}
}

func (a *app) flushActivity(ctx context.Context) {
	// A configuration transaction can read before its first write. Keep the batch
	// pending so this write cannot invalidate that transaction's SQLite snapshot.
	if !a.mu.TryLock() {
		return
	}
	defer a.mu.Unlock()
	a.writeActivity(ctx)
}

// writeActivity is called with app.mu held, in the same lock order as a reset.
func (a *app) writeActivity(ctx context.Context) {
	a.presence.mu.Lock()
	defer a.presence.mu.Unlock()
	pending := a.presence.pending
	if len(pending) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := a.storeActivity(ctx, pending); err != nil {
		if ctx.Err() == nil {
			log.Printf("cannot save client activity: %v", err)
		}
		return
	}
	clear(pending)
}

func (a *app) storeActivity(ctx context.Context, pending map[string]pendingActivity) error {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for uuid, update := range pending {
		if _, err := tx.ExecContext(ctx, `UPDATE subscriptions
			SET last_seen_at = max(coalesce(last_seen_at, 0), ?),
			    upload_bytes = upload_bytes + ?, download_bytes = download_bytes + ?
			WHERE uuid = ? AND created_at <= ?`,
			update.seen, update.upload, update.download, uuid, update.seen); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func clientTime(timestamp int64) time.Time {
	return time.Unix(timestamp, 0).UTC()
}

func (a *app) resetTraffic(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.subscriptionByID(w, r)
	if !ok {
		return
	}
	a.presence.mu.Lock()
	defer a.presence.mu.Unlock()
	if _, err := a.db.ExecContext(r.Context(), "UPDATE subscriptions SET upload_bytes = 0, download_bytes = 0 WHERE id = ?", s.ID); err != nil {
		serverError(w)
		return
	}
	if update, ok := a.presence.pending[s.UUID]; ok {
		update.upload, update.download = 0, 0
		a.presence.pending[s.UUID] = update
	}
	a.redirect(w, r, "/subscriptions/"+r.PathValue("id")+"?traffic-reset=1")
}

func (a *app) subscriptionActivity(w http.ResponseWriter, r *http.Request) {
	online := a.onlineClients()
	rows, err := a.db.QueryContext(r.Context(), "SELECT id, enabled, uuid, last_seen_at, upload_bytes, download_bytes FROM subscriptions")
	if err != nil {
		serverError(w)
		return
	}
	defer rows.Close()
	type activity struct {
		Status   string     `json:"status"`
		LastSeen *time.Time `json:"lastSeen"`
		Traffic  string     `json:"traffic"`
		Upload   string     `json:"upload"`
		Download string     `json:"download"`
	}
	clients := make(map[int64]activity)
	for rows.Next() {
		var id int64
		var s Subscription
		if err := rows.Scan(&id, &s.Enabled, &s.UUID, &s.LastSeenAt, &s.UploadBytes, &s.DownloadBytes); err != nil {
			serverError(w)
			return
		}
		client := activity{
			Status: online.status(s.Enabled, s.UUID), Traffic: s.Traffic(),
			Upload: formatBytes(s.UploadBytes), Download: formatBytes(s.DownloadBytes),
		}
		if s.LastSeenAt.Valid {
			timestamp := clientTime(s.LastSeenAt.Int64)
			client.LastSeen = &timestamp
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
