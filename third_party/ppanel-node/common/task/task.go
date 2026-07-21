package task

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/perfect-panel/ppanel-node/common/logx"
)

type Task struct {
	Name     string
	Interval time.Duration
	Execute  func(context.Context) error
	Access   sync.RWMutex
	Running  bool
	ReloadCh chan struct{}
	Stop     chan struct{}
}

func (t *Task) Start(first bool) error {
	t.Access.Lock()
	if t.Running {
		t.Access.Unlock()
		return nil
	}
	t.Running = true
	t.Stop = make(chan struct{})
	t.Access.Unlock()
	go func() {
		timer := time.NewTimer(t.Interval)
		defer timer.Stop()
		if first {
			if err := t.ExecuteWithTimeout(); err != nil {
				return
			}
		}

		for {
			timer.Reset(t.Interval)
			select {
			case <-timer.C:
				// continue
			case <-t.Stop:
				return
			}

			if err := t.ExecuteWithTimeout(); err != nil {
				logx.Task(t.Name).WithError(err).Error("任务执行失败")
				return
			}
		}
	}()

	return nil
}

func (t *Task) ExecuteWithTimeout() error {
	ctx, cancel := context.WithTimeout(context.Background(), min(5*t.Interval, 5*time.Minute))
	defer cancel()
	done := make(chan error, 1)

	go func() {
		done <- t.Execute(ctx)
	}()

	select {
	case <-ctx.Done():
		logger := logx.Task(t.Name)
		logger.Warn("任务执行超时，已投递重载信号")
		if t.ReloadCh != nil {
			select {
			case t.ReloadCh <- struct{}{}:
			default:
			}
		} else {
			logger.Error("任务执行超时但重载通道为空")
		}
		return nil
	case err := <-done:
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		return err
	}
}

func (t *Task) safeStop() {
	t.Access.Lock()
	if t.Running {
		t.Running = false
		close(t.Stop)
	}
	t.Access.Unlock()
}

func (t *Task) Close() {
	t.safeStop()
	logx.Task(t.Name).Warn("任务已停止")
}
