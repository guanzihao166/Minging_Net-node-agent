package rate

import (
	"github.com/juju/ratelimit"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type Writer struct {
	writer  buf.Writer
	limiter *ratelimit.Bucket
	resolve func() *ratelimit.Bucket
}

func NewRateLimitWriter(writer buf.Writer, limiter *ratelimit.Bucket) buf.Writer {
	return &Writer{
		writer:  writer,
		limiter: limiter,
	}
}

// NewDynamicRateLimitWriter keeps existing Xray connections aligned with the
// current control-plane policy. The resolver is evaluated for every write so a
// user limit change does not require reconnecting the client.
func NewDynamicRateLimitWriter(writer buf.Writer, resolve func() *ratelimit.Bucket) buf.Writer {
	return &Writer{writer: writer, resolve: resolve}
}

func (w *Writer) Close() error {
	return common.Close(w.writer)
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	limiter := w.limiter
	if w.resolve != nil {
		limiter = w.resolve()
	}
	if limiter != nil {
		if w.resolve != nil && limiter.Capacity() == 1 {
			// A capacity-one bucket is the active zero-allocation sentinel. Do
			// not park an existing connection behind a full-buffer wait: poll the
			// resolver once per 100ms so it picks up a newly assigned share.
			for limiter != nil && limiter.Capacity() == 1 {
				limiter.Wait(1)
				limiter = w.resolve()
			}
		}
		if limiter != nil {
			limiter.Wait(int64(mb.Len()))
		}
	}
	return w.writer.WriteMultiBuffer(mb)
}
