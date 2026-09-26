package rate

import (
	"context"
	"errors"
	"github.com/juju/ratelimit"
	"github.com/xtls/xray-core/common/buf"
	"io"
	"sync"
	"testing"
	"time"
)

type discard struct{}

func (discard) WriteMultiBuffer(mb buf.MultiBuffer) error { buf.ReleaseMulti(mb); return nil }
func block(size int) buf.MultiBuffer                      { return buf.MergeBytes(nil, make([]byte, size)) }
func bucket(rate int64) *ratelimit.Bucket {
	b := ratelimit.NewBucketWithQuantum(10*time.Millisecond, rate/10, rate/100)
	b.TakeAvailable(b.Capacity())
	return b
}
func TestParallelTransfersConsumeSharedTokensWithoutDebt(t *testing.T) {
	b := bucket(1_000_000)
	start := time.Now()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := NewDynamicRateLimitWriters(context.Background(), discard{}, func() []*ratelimit.Bucket { return []*ratelimit.Bucket{b} })
			if err := w.WriteMultiBuffer(block(125_000)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	if elapsed < 900*time.Millisecond {
		t.Fatalf("parallel bypass: %s", elapsed)
	}
	if b.Available() < 0 {
		t.Fatal("negative debt queued")
	}
}
func TestPolicyChangeAndCancellationWakePausedTransfers(t *testing.T) {
	paused := ratelimit.NewBucketWithQuantum(100*time.Millisecond, 1, 1)
	var mu sync.Mutex
	current := paused
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := NewDynamicRateLimitWriters(ctx, discard{}, func() []*ratelimit.Bucket { mu.Lock(); defer mu.Unlock(); return []*ratelimit.Bucket{current} })
	done := make(chan error, 1)
	go func() { done <- w.WriteMultiBuffer(block(1024)) }()
	select {
	case <-done:
		t.Fatal("zero allocation sent data")
	case <-time.After(30 * time.Millisecond):
	}
	mu.Lock()
	current = nil
	mu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("old policy kept transfer blocked")
	}
	mu.Lock()
	current = paused
	mu.Unlock()
	go func() { done <- w.WriteMultiBuffer(block(1024)) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not wake transfer")
	}
}

type finalReader struct{ done bool }

func (r *finalReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.done {
		return nil, io.EOF
	}
	r.done = true
	return block(20_000), io.EOF
}
func TestUploadReaderPacesAndPreservesFinalPayload(t *testing.T) {
	b := bucket(100_000)
	r := NewDynamicRateLimitReader(context.Background(), &finalReader{}, func() []*ratelimit.Bucket { return []*ratelimit.Bucket{b} })
	start := time.Now()
	total := int32(0)
	for {
		mb, err := r.ReadMultiBuffer()
		total += mb.Len()
		buf.ReleaseMulti(mb)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if total != 20_000 || time.Since(start) < 180*time.Millisecond {
		t.Fatalf("upload payload=%d elapsed=%s", total, time.Since(start))
	}
}
