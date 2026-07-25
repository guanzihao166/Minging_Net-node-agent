package core

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

func TestBuildSS2022UserPreservesDecodedKey(t *testing.T) {
	rawKey := bytes.Repeat([]byte{0x7c}, 32)
	encoded := base64.StdEncoding.EncodeToString(rawKey)
	user := buildSSUser("inbound-1", &panel.UserInfo{Id: 7, Uuid: encoded}, "2022-blake3-aes-256-gcm", "")
	memory, err := user.ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	account, ok := memory.Account.(*shadowsocks_2022.MemoryAccount)
	if !ok {
		t.Fatalf("account type = %T", memory.Account)
	}
	if account.Key != encoded {
		t.Fatalf("account key changed: got %q, want %q", account.Key, encoded)
	}
}

func TestBuildSS2022UserRetainsLegacyRawKeyCompatibility(t *testing.T) {
	rawText := "12345678901234567890123456789012"
	want := base64.StdEncoding.EncodeToString([]byte(rawText))
	user := buildSSUser("inbound-1", &panel.UserInfo{Id: 7, Uuid: rawText}, "2022-blake3-aes-256-gcm", "")
	memory, err := user.ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	account := memory.Account.(*shadowsocks_2022.MemoryAccount)
	if account.Key != want {
		t.Fatalf("legacy account key = %q, want %q", account.Key, want)
	}
}
