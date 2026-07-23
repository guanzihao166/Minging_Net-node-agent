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
		limiter.Wait(int64(mb.Len()))
	}
	return w.writer.WriteMultiBuffer(mb)
}
