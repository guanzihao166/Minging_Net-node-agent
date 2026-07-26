package hostmetrics

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	procStatPath    = "/proc/stat"
	procMemInfoPath = "/proc/meminfo"
	procNetDevPath  = "/proc/net/dev"
	procUptimePath  = "/proc/uptime"
)

type Snapshot struct {
	SampledAt          time.Time
	CPUPercent         float64
	MemoryPercent      float64
	MemoryUsedBytes    uint64
	MemoryTotalBytes   uint64
	NetworkReceiveBPS  uint64
	NetworkTransmitBPS uint64
	UptimeSeconds      uint64
}

type cpuCounters struct {
	total uint64
	idle  uint64
}

type networkCounters struct {
	receiveBytes  uint64
	transmitBytes uint64
}

type Collector struct {
	mu              sync.Mutex
	now             func() time.Time
	readFile        func(string) ([]byte, error)
	previousAt      time.Time
	previousCPU     cpuCounters
	previousNetwork networkCounters
	hasPrevious     bool
}

func NewCollector() *Collector {
	return &Collector{now: time.Now, readFile: os.ReadFile}
}

func (c *Collector) Sample() (Snapshot, error) {
	if c == nil {
		return Snapshot{}, errors.New("host metrics collector is nil")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now().UTC()
	statRaw, err := c.readFile(procStatPath)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read cpu counters: %w", err)
	}
	memRaw, err := c.readFile(procMemInfoPath)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read memory counters: %w", err)
	}
	netRaw, err := c.readFile(procNetDevPath)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read network counters: %w", err)
	}
	uptimeRaw, err := c.readFile(procUptimePath)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read uptime: %w", err)
	}

	cpu, err := parseCPUCounters(statRaw)
	if err != nil {
		return Snapshot{}, err
	}
	memoryUsed, memoryTotal, memoryPercent, err := parseMemory(memRaw)
	if err != nil {
		return Snapshot{}, err
	}
	network, err := parseNetworkCounters(netRaw)
	if err != nil {
		return Snapshot{}, err
	}
	uptimeSeconds, err := parseUptime(uptimeRaw)
	if err != nil {
		return Snapshot{}, err
	}

	snapshot := Snapshot{
		SampledAt: now, MemoryPercent: memoryPercent,
		MemoryUsedBytes: memoryUsed, MemoryTotalBytes: memoryTotal,
		UptimeSeconds: uptimeSeconds,
	}
	if c.hasPrevious {
		elapsed := now.Sub(c.previousAt).Seconds()
		if elapsed > 0 {
			if cpu.total >= c.previousCPU.total && cpu.idle >= c.previousCPU.idle {
				totalDelta := cpu.total - c.previousCPU.total
				idleDelta := cpu.idle - c.previousCPU.idle
				if totalDelta > 0 && idleDelta <= totalDelta {
					snapshot.CPUPercent = clampPercent(float64(totalDelta-idleDelta) * 100 / float64(totalDelta))
				}
			}
			if network.receiveBytes >= c.previousNetwork.receiveBytes {
				snapshot.NetworkReceiveBPS = ratePerSecond(network.receiveBytes-c.previousNetwork.receiveBytes, elapsed)
			}
			if network.transmitBytes >= c.previousNetwork.transmitBytes {
				snapshot.NetworkTransmitBPS = ratePerSecond(network.transmitBytes-c.previousNetwork.transmitBytes, elapsed)
			}
		}
	}
	c.previousAt = now
	c.previousCPU = cpu
	c.previousNetwork = network
	c.hasPrevious = true
	return snapshot, nil
}

func parseCPUCounters(raw []byte) (cpuCounters, error) {
	line, _, _ := strings.Cut(string(raw), "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuCounters{}, errors.New("cpu counters are invalid")
	}
	values := make([]uint64, 0, 8)
	for _, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return cpuCounters{}, errors.New("cpu counters are invalid")
		}
		values = append(values, value)
		if len(values) == 8 {
			break
		}
	}
	if len(values) < 4 {
		return cpuCounters{}, errors.New("cpu counters are incomplete")
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	idle := values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	return cpuCounters{total: total, idle: idle}, nil
}

func parseMemory(raw []byte) (usedBytes, totalBytes uint64, percent float64, err error) {
	values := make(map[string]uint64)
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr == nil {
			values[key] = value * 1024
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return 0, 0, 0, scanErr
	}
	totalBytes = values["MemTotal"]
	if totalBytes == 0 {
		return 0, 0, 0, errors.New("memory total is unavailable")
	}
	available := values["MemAvailable"]
	if available == 0 {
		available = values["MemFree"] + values["Buffers"] + values["Cached"]
	}
	if available > totalBytes {
		available = totalBytes
	}
	usedBytes = totalBytes - available
	percent = clampPercent(float64(usedBytes) * 100 / float64(totalBytes))
	return usedBytes, totalBytes, percent, nil
}

func parseNetworkCounters(raw []byte) (networkCounters, error) {
	var result networkCounters
	var interfaces int
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := scanner.Text()
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		if name == "" || name == "lo" {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 16 {
			return networkCounters{}, errors.New("network counters are incomplete")
		}
		receive, receiveErr := strconv.ParseUint(fields[0], 10, 64)
		transmit, transmitErr := strconv.ParseUint(fields[8], 10, 64)
		if receiveErr != nil || transmitErr != nil {
			return networkCounters{}, errors.New("network counters are invalid")
		}
		result.receiveBytes += receive
		result.transmitBytes += transmit
		interfaces++
	}
	if err := scanner.Err(); err != nil {
		return networkCounters{}, err
	}
	if interfaces == 0 {
		return networkCounters{}, errors.New("no non-loopback network interface found")
	}
	return result, nil
}

func parseUptime(raw []byte) (uint64, error) {
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return 0, errors.New("uptime is invalid")
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || seconds < 0 || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return 0, errors.New("uptime is invalid")
	}
	return uint64(seconds), nil
}

func ratePerSecond(delta uint64, elapsed float64) uint64 {
	if elapsed <= 0 {
		return 0
	}
	rate := float64(delta) / elapsed
	if rate <= 0 {
		return 0
	}
	if rate >= float64(^uint64(0)) {
		return ^uint64(0)
	}
	return uint64(math.Round(rate))
}

func clampPercent(value float64) float64 {
	if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	if value > 100 {
		return 100
	}
	return math.Round(value*100) / 100
}
