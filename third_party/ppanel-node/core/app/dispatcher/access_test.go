package dispatcher

import (
	"strings"
	"testing"
	"time"
)

func TestAccessRecorderEmitsCheckpointAndFinalDeltasWithoutDoubleCounting(t *testing.T) {
	current := time.Unix(1700000000, 0).UTC()
	recorder := NewAccessRecorder()
	recorder.now = func() time.Time { return current }
	recorder.SetIdentityResolver(func(userKey, inboundTag string) (int64, int64, bool) {
		return 901, 81, userKey == "user" && inboundTag == "inbound-81"
	})
	session := recorder.Start("user", "inbound-81", "VIDEO.Example.", "tcp", 443)
	if session == nil {
		t.Fatal("access session was not created")
	}
	session.UpdateTarget("xn--bcher-kva.example", "TLS")
	session.AddUpload(100)
	session.AddDownload(200)
	if samples := recorder.Drain(); len(samples) != 0 {
		t.Fatalf("early drain = %#v", samples)
	}
	current = current.Add(5 * time.Minute)
	checkpoint := recorder.Drain()
	if len(checkpoint) != 1 || !checkpoint[0].Active || checkpoint[0].ConnectionCount != 1 || checkpoint[0].UploadBytes != 100 || checkpoint[0].DownloadBytes != 200 {
		t.Fatalf("checkpoint = %#v", checkpoint)
	}
	session.AddDownload(50)
	current = current.Add(time.Minute)
	session.Close()
	final := recorder.Drain()
	if len(final) != 1 || final[0].Active || final[0].EndedAt == nil || final[0].ConnectionCount != 0 || final[0].UploadBytes != 0 || final[0].DownloadBytes != 50 {
		t.Fatalf("final = %#v", final)
	}
	if final[0].SessionKey != checkpoint[0].SessionKey || len(final[0].SessionKey) != 64 {
		t.Fatalf("session keys = %q/%q", checkpoint[0].SessionKey, final[0].SessionKey)
	}
}

func TestAccessRecorderBoundsPerUserDomainsAndGlobalSessions(t *testing.T) {
	current := time.Unix(1700000000, 0).UTC()
	recorder := NewAccessRecorder()
	recorder.now = func() time.Time { return current }
	recorder.maxDomainsPerUserKey = 2
	recorder.maxSessions = 3
	recorder.checkpointInterval = time.Second
	recorder.SetIdentityResolver(func(string, string) (int64, int64, bool) { return 901, 81, true })
	for index, host := range []string{"a.example", "b.example", "c.example"} {
		session := recorder.Start("user", "inbound-81", host, "tcp", uint16(440+index))
		if session == nil {
			t.Fatalf("session %d was dropped early", index)
		}
	}
	if session := recorder.Start("user", "inbound-81", "d.example", "tcp", 444); session != nil || recorder.DroppedSessions() != 1 {
		t.Fatalf("session cap = %#v, dropped=%d", session, recorder.DroppedSessions())
	}
	current = current.Add(time.Second)
	samples := recorder.Drain()
	overflow := 0
	for _, sample := range samples {
		if sample.Host == accessOverflowHost {
			overflow++
		}
	}
	if len(samples) != 3 || overflow != 1 {
		t.Fatalf("bounded samples = %#v", samples)
	}
}

func TestNormalizeAccessHostCanonicalizesIPAndIDN(t *testing.T) {
	for input, expected := range map[string]string{
		"::ffff:192.0.2.1": "192.0.2.1",
		"Bücher.Example.":  "xn--bcher-kva.example",
	} {
		actual, ok := normalizeAccessHost(input)
		if !ok || actual != expected {
			t.Fatalf("normalizeAccessHost(%q) = %q/%v, want %q", input, actual, ok, expected)
		}
	}
	if _, ok := normalizeAccessHost(strings.Repeat("a", 64) + ".example"); ok {
		t.Fatal("oversized DNS label was accepted")
	}
}
