package inbound

import (
	"encoding/json"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func TestBuildVlessDecryptionUsesServerFields(t *testing.T) {
	got, err := buildVlessDecryption(&panel.Protocol{
		Encryption:              "mlkem768x25519plus",
		EncryptionMode:          "native",
		EncryptionRTT:           "0rtt",
		EncryptionTicket:        "600s",
		EncryptionServerPadding: "100-111-1111.75-0-111.50-0-3333",
		EncryptionClientPadding: "client-padding",
		EncryptionPrivateKey:    "ptjHQxBQxTJ9MWr2cd5qWIflBSACHOevTauCQwa_71U",
	})
	if err != nil {
		t.Fatalf("buildVlessDecryption() error = %v", err)
	}
	want := "mlkem768x25519plus.native.600s.100-111-1111.75-0-111.50-0-3333.ptjHQxBQxTJ9MWr2cd5qWIflBSACHOevTauCQwa_71U"
	if got != want {
		t.Fatalf("buildVlessDecryption() = %s, want %s", got, want)
	}
}

func TestBuildVlessDecryptionAddsSecondsToNumericTicket(t *testing.T) {
	got, err := buildVlessDecryption(&panel.Protocol{
		Encryption:           "mlkem768x25519plus",
		EncryptionMode:       "native",
		EncryptionTicket:     "600",
		EncryptionPrivateKey: "private-key",
	})
	if err != nil {
		t.Fatalf("buildVlessDecryption() error = %v", err)
	}
	want := "mlkem768x25519plus.native.600s.private-key"
	if got != want {
		t.Fatalf("buildVlessDecryption() = %s, want %s", got, want)
	}
}

func TestBuildVLessUsesEncryptionTicketInDecryption(t *testing.T) {
	inbound := &coreConf.InboundDetourConfig{}
	err := buildVLess(&panel.NodeInfo{
		Protocol: &panel.Protocol{
			Transport:               "tcp",
			Encryption:              "mlkem768x25519plus",
			EncryptionMode:          "native",
			EncryptionRTT:           "0rtt",
			EncryptionTicket:        "600s",
			EncryptionServerPadding: "100-111-1111.75-0-111.50-0-3333",
			EncryptionPrivateKey:    "ptjHQxBQxTJ9MWr2cd5qWIflBSACHOevTauCQwa_71U",
		},
	}, inbound)
	if err != nil {
		t.Fatalf("buildVLess() error = %v", err)
	}

	var settings struct {
		Decryption string `json:"decryption"`
	}
	if err := json.Unmarshal(*inbound.Settings, &settings); err != nil {
		t.Fatalf("unmarshal vless settings error = %v", err)
	}
	want := "mlkem768x25519plus.native.600s.100-111-1111.75-0-111.50-0-3333.ptjHQxBQxTJ9MWr2cd5qWIflBSACHOevTauCQwa_71U"
	if settings.Decryption != want {
		t.Fatalf("vless decryption = %s, want %s", settings.Decryption, want)
	}
}
