package hostmetrics

import (
	"math"
	"testing"
	"time"
)

func TestCollectorCalculatesCPUAndAggregateNetworkRates(t *testing.T) {
	collector := NewCollector()
	now := time.Date(2026, 7, 26, 8, 0, 0, 0, time.UTC)
	collector.now = func() time.Time { return now }
	files := map[string]string{
		procStatPath:    "cpu  100 0 50 850 0 0 0 0\n",
		procMemInfoPath: "MemTotal: 1000 kB\nMemAvailable: 250 kB\n",
		procNetDevPath:  "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\nlo: 999 0 0 0 0 0 0 0 999 0 0 0 0 0 0 0\neth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\neth1: 500 0 0 0 0 0 0 0 700 0 0 0 0 0 0 0\n",
		procUptimePath:  "123.40 10.00\n",
	}
	collector.readFile = func(path string) ([]byte, error) { return []byte(files[path]), nil }

	first, err := collector.Sample()
	if err != nil {
		t.Fatal(err)
	}
	if first.CPUPercent != 0 || first.NetworkReceiveBPS != 0 || first.NetworkTransmitBPS != 0 {
		t.Fatalf("first rate sample = %#v", first)
	}
	if first.MemoryUsedBytes != 750*1024 || first.MemoryTotalBytes != 1000*1024 || first.MemoryPercent != 75 || first.UptimeSeconds != 123 {
		t.Fatalf("first memory/uptime sample = %#v", first)
	}

	now = now.Add(5 * time.Second)
	files[procStatPath] = "cpu  130 0 60 910 0 0 0 0\n"
	files[procNetDevPath] = "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\neth0: 5000 0 0 0 0 0 0 0 9000 0 0 0 0 0 0 0\neth1: 2500 0 0 0 0 0 0 0 3700 0 0 0 0 0 0 0\n"
	second, err := collector.Sample()
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(second.CPUPercent-40) > 0.01 {
		t.Fatalf("CPUPercent = %v, want 40", second.CPUPercent)
	}
	if second.NetworkReceiveBPS != 1200 || second.NetworkTransmitBPS != 2000 {
		t.Fatalf("network rate = %d/%d, want 1200/2000", second.NetworkReceiveBPS, second.NetworkTransmitBPS)
	}
}

func TestMemoryFallbackAndCounterReset(t *testing.T) {
	used, total, percent, err := parseMemory([]byte("MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 150 kB\n"))
	if err != nil {
		t.Fatal(err)
	}
	if used != 700*1024 || total != 1000*1024 || percent != 70 {
		t.Fatalf("memory = %d/%d %.2f", used, total, percent)
	}
	if _, err := parseNetworkCounters([]byte("lo: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n")); err == nil {
		t.Fatal("loopback-only network sample must fail")
	}
}
