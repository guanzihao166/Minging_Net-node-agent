package rate

import (
	"context"
	"sync"
	"time"

	"github.com/juju/ratelimit"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

// Multiple policy budgets are acquired atomically. Never reserve negative
// token debt: queued debt survives limit changes and grows with every stream.
var tokenMu sync.Mutex

type budget struct {
	ctx     context.Context
	cancel  context.CancelFunc
	resolve func() []*ratelimit.Bucket
}

func newBudget(ctx context.Context, resolve func() []*ratelimit.Bucket) *budget {
	ctx, cancel := context.WithCancel(ctx)
	return &budget{ctx: ctx, cancel: cancel, resolve: resolve}
}
func (b *budget) take(size int64) error {
	for size > 0 {
		if err := b.ctx.Err(); err != nil {
			return err
		}
		buckets := b.resolve()
		tokenMu.Lock()
		n := size
		for _, bucket := range buckets {
			if bucket == nil {
				continue
			}
			if bucket.Capacity() == 1 {
				n = 0
				break
			} // active zero allocation
			if available := bucket.Available(); available < n {
				n = available
			}
		}
		if n > 0 {
			for _, bucket := range buckets {
				if bucket != nil {
					bucket.TakeAvailable(n)
				}
			}
		}
		tokenMu.Unlock()
		if n > 0 {
			size -= n
			continue
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-b.ctx.Done():
			timer.Stop()
			return b.ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

type Writer struct {
	writer buf.Writer
	budget *budget
}

func NewRateLimitWriter(writer buf.Writer, limiter *ratelimit.Bucket) buf.Writer {
	return NewDynamicRateLimitWriters(context.Background(), writer, func() []*ratelimit.Bucket { return []*ratelimit.Bucket{limiter} })
}
func NewDynamicRateLimitWriter(writer buf.Writer, resolve func() *ratelimit.Bucket) buf.Writer {
	return NewDynamicRateLimitWriters(context.Background(), writer, func() []*ratelimit.Bucket { return []*ratelimit.Bucket{resolve()} })
}
func NewDynamicRateLimitWriters(ctx context.Context, writer buf.Writer, resolve func() []*ratelimit.Bucket) buf.Writer {
	return &Writer{writer: writer, budget: newBudget(ctx, resolve)}
}
func (w *Writer) Close() error { w.budget.cancel(); return common.Close(w.writer) }
func (w *Writer) Interrupt()   { w.budget.cancel(); common.Interrupt(w.writer) }
func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer func() { buf.ReleaseMulti(mb) }()
	for len(mb) > 0 {
		first := mb[0]
		if first == nil {
			mb = mb[1:]
			continue
		}
		if err := w.budget.take(int64(first.Len())); err != nil {
			return err
		}
		mb[0] = nil
		mb = mb[1:]
		// Preserve datagram boundaries, but never forward an unpaced whole batch.
		if err := w.writer.WriteMultiBuffer(buf.MultiBuffer{first}); err != nil {
			return err
		}
	}
	return nil
}

type Reader struct {
	reader     buf.Reader
	budget     *budget
	pending    buf.MultiBuffer
	pendingErr error
}

func NewDynamicRateLimitReader(ctx context.Context, reader buf.Reader, resolve func() []*ratelimit.Bucket) buf.Reader {
	return &Reader{reader: reader, budget: newBudget(ctx, resolve)}
}
func (r *Reader) Interrupt()   { r.budget.cancel(); common.Interrupt(r.reader) }
func (r *Reader) Close() error { r.budget.cancel(); return common.Close(r.reader) }
func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	for {
		if len(r.pending) == 0 {
			if r.pendingErr != nil {
				return nil, r.pendingErr
			}
			r.pending, r.pendingErr = r.reader.ReadMultiBuffer()
		}
		if len(r.pending) == 0 {
			return nil, r.pendingErr
		}
		first := r.pending[0]
		r.pending[0] = nil
		r.pending = r.pending[1:]
		if first == nil {
			continue
		}
		if err := r.budget.take(int64(first.Len())); err != nil {
			first.Release()
			buf.ReleaseMulti(r.pending)
			r.pending = nil
			return nil, err
		}
		// Return any EOF only after all bytes from the final read are delivered.
		return buf.MultiBuffer{first}, nil
	}
}
