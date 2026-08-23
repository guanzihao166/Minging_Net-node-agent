package runtime

import (
	"context"

	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
	"github.com/guanzihao166/iepl-node-agent/internal/state"
)

type Status struct {
	Running bool
	Version string
}

type Runtime interface {
	ApplyConfig(context.Context, agentprotocol.DesiredConfig) error
	// DisconnectUsers closes data-plane links for users that are removed or
	// changed by the next snapshot before the runtime is rebuilt.
	DisconnectUsers(context.Context, []agentprotocol.UserCredential) error
	// DisconnectSubscribers closes only the selected subscribers' live links
	// without rebuilding the Xray core or touching other users.
	DisconnectSubscribers(context.Context, []int64) error
	ApplyUsers(context.Context, []agentprotocol.UserCredential) error
	CollectTraffic(context.Context) ([]state.TrafficDelta, error)
	CollectAccess(context.Context) ([]agentprotocol.AccessItem, error)
	RequeueAccess([]agentprotocol.AccessItem)
	CollectOnline(context.Context) ([]agentprotocol.OnlineUser, error)
	Status(context.Context) Status
	Close() error
}
