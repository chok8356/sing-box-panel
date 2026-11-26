package singbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"sing-box-panel/internal/singbox/connectionapi"
)

// ConnectionAPI configures the local API used to monitor authenticated connections.
type ConnectionAPI struct {
	port   int
	secret string
}

func NewConnectionAPI() (*ConnectionAPI, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	return &ConnectionAPI{port: listener.Addr().(*net.TCPAddr).Port, secret: rand.Text()}, nil
}

func (a *ConnectionAPI) Configure(body []byte) ([]byte, error) {
	root, err := decodeRuntimeObject(body)
	if err != nil {
		return nil, err
	}
	services, ok := root["services"].([]any)
	if root["services"] != nil && !ok {
		return nil, fmt.Errorf("server services must be an array")
	}
	root["services"] = append(services, map[string]any{
		"type": "api", "tag": fmt.Sprintf("panel-activity-%d", a.port),
		"listen": "127.0.0.1", "listen_port": a.port, "secret": a.secret,
	})
	return json.MarshalIndent(root, "", "  ")
}

func (a *ConnectionAPI) Subscribe(ctx context.Context, receive func(*connectionapi.ConnectionEvents) bool) error {
	client, err := grpc.NewClient(fmt.Sprintf("passthrough:///127.0.0.1:%d", a.port),
		grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithNoProxy())
	if err != nil {
		return err
	}
	defer client.Close()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+a.secret)
	stream, err := connectionapi.NewStartedServiceClient(client).SubscribeConnections(ctx, &connectionapi.SubscribeConnectionsRequest{})
	if err != nil {
		return err
	}
	for {
		batch, err := stream.Recv()
		if err != nil {
			return err
		}
		if !receive(batch) {
			return nil
		}
	}
}

// ManagedInbounds maps the runtime tags of the inbounds the panel populates to their types.
func ManagedInbounds(body []byte) (map[string]string, error) {
	root, err := decodeRuntimeObject(body)
	if err != nil {
		return nil, err
	}
	inbounds, _ := root["inbounds"].([]any)
	managed := make(map[string]string)
	for i, value := range inbounds {
		inbound, _ := value.(map[string]any)
		if !managesUsers(inbound) {
			continue
		}
		tag, _ := inbound["tag"].(string)
		if tag == "" {
			tag = strconv.Itoa(i)
		}
		managed[tag], _ = inbound["type"].(string)
	}
	return managed, nil
}

// The generated config can exceed the editor's size limit after adding clients.
func decodeRuntimeObject(body []byte) (map[string]any, error) {
	var root map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return nil, err
	}
	if root == nil {
		return nil, fmt.Errorf("runtime config must be a JSON object")
	}
	return root, nil
}
