package identity

import (
	"encoding/json"
	"errors"
	"github.com/guanzihao166/iepl-node-agent/internal/config"
	"net/url"
)

// UpdateControlEndpoint accepts only a control endpoint advertised over an
// authenticated server session. Persist before using it on the next reconnect.
func UpdateControlEndpoint(cfg config.Config, identity *Identity, endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "wss" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Path != "/api/v1/agent/connect" || (u.Port() != "" && u.Port() != "443") {
		return errors.New("advertised control endpoint is invalid")
	}
	updated := *identity
	updated.WSSURL = endpoint
	raw, err := json.Marshal(updated)
	if err != nil {
		return err
	}
	if err = atomicWrite(cfg.IdentityPath(), append(raw, '\n'), 0600); err != nil {
		return err
	}
	identity.WSSURL = endpoint
	return nil
}
