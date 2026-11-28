package panel

import (
	"testing"
	"time"

	"sing-box-panel/internal/singbox/connectionapi"
)

func TestConnectionTrafficAcrossSnapshots(t *testing.T) {
	session := presenceSession{
		inbounds:    map[string]string{"vless": "vless"},
		names:       map[string]string{"Client": "client-id"},
		connections: make(map[string]trackedConnection),
	}
	pending := make(map[string]pendingActivity)
	var online onlineClients
	now := time.Now()
	apply := func(reset bool, events ...*connectionapi.ConnectionEvent) {
		online = session.apply(&connectionapi.ConnectionEvents{Reset_: reset, Events: events}, online, pending, now)
	}
	connection := func(upload, download, closed int64) *connectionapi.Connection {
		return &connectionapi.Connection{
			Inbound: "vless", InboundType: "vless", User: "Client",
			UplinkTotal: upload, DownlinkTotal: download, ClosedAt: closed,
		}
	}
	apply(true,
		&connectionapi.ConnectionEvent{Id: "old", Connection: connection(100, 200, now.UnixMilli())},
		&connectionapi.ConnectionEvent{Id: "live", Connection: connection(100, 200, 0)},
	)
	apply(false, &connectionapi.ConnectionEvent{
		Id: "live", Type: connectionapi.ConnectionEventType_CONNECTION_EVENT_UPDATE, UplinkDelta: 10, DownlinkDelta: 20,
	})
	if got := pending["client-id"]; got.upload != 10 || got.download != 20 {
		t.Fatalf("traffic after snapshot and update = %+v", got)
	}
	final := &connectionapi.ConnectionEvent{
		Id: "live", Type: connectionapi.ConnectionEventType_CONNECTION_EVENT_CLOSED,
		Connection: connection(115, 230, now.UnixMilli()),
	}
	apply(false, final, final)
	apply(true, final)
	if got := pending["client-id"]; got.upload != 15 || got.download != 30 {
		t.Fatalf("traffic after close and replay = %+v", got)
	}
	apply(false,
		&connectionapi.ConnectionEvent{Id: "short", Connection: connection(2, 4, 0)},
		&connectionapi.ConnectionEvent{Id: "short", Type: connectionapi.ConnectionEventType_CONNECTION_EVENT_CLOSED,
			Connection: connection(3, 6, now.UnixMilli())},
	)
	if got := pending["client-id"]; got.upload != 18 || got.download != 36 {
		t.Fatalf("traffic after a short connection = %+v", got)
	}
}
