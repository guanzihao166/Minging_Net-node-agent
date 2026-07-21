package conf

import (
	"fmt"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/perfect-panel/ppanel-node/common/logx"
)

func (p *Conf) Watch(filePath string, reload func()) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("new watcher error: %s", err)
	}
	go func() {
		var pre time.Time
		defer watcher.Close()
		for {
			select {
			case e := <-watcher.Events:
				if e.Has(fsnotify.Chmod) {
					continue
				}
				if pre.Add(10 * time.Second).After(time.Now()) {
					continue
				}
				pre = time.Now()
				go func() {
					time.Sleep(5 * time.Second)
					logx.Component("watcher").Info("检测到配置文件变化，已投递重载信号")
					reload()
				}()
			case err := <-watcher.Errors:
				if err != nil {
					logx.Component("watcher").WithError(err).Error("配置文件监听失败")
				}
			}
		}
	}()
	err = watcher.Add(filePath)
	if err != nil {
		return fmt.Errorf("watch file error: %s", err)
	}
	return nil
}
