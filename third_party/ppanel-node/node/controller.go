package node

import (
	"context"
	"errors"
	"fmt"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/logx"
	"github.com/perfect-panel/ppanel-node/common/task"
	vCore "github.com/perfect-panel/ppanel-node/core"
	"github.com/perfect-panel/ppanel-node/limiter"
)

type Controller struct {
	server                  *vCore.XrayCore
	apiClient               *panel.NodeClient
	tag                     string
	limiter                 *limiter.Limiter
	userList                []panel.UserInfo
	aliveMap                map[int]int
	info                    *panel.NodeInfo
	userListMonitorPeriodic *task.Task
	userReportPeriodic      *task.Task
	renewCertPeriodic       *task.Task
	onlineIpReportPeriodic  *task.Task
}

// NewController return a Node controller with default parameters.
func NewController(core *vCore.XrayCore, api *panel.NodeClient, info *panel.NodeInfo) *Controller {
	controller := &Controller{
		server:    core,
		apiClient: api,
		info:      info,
	}
	return controller
}

// Start implement the Start() function of the service interface
func (c *Controller) Start() error {
	var err error
	// Update user
	c.userList, err = c.apiClient.GetUserList(context.Background())
	if err != nil {
		return fmt.Errorf("get user list error: %s", err)
	}
	if len(c.userList) == 0 {
		return errors.New("add users error: not have any user")
	}
	c.aliveMap, err = c.apiClient.GetUserAlive()
	if err != nil {
		return fmt.Errorf("failed to get user alive list: %s", err)
	}
	c.tag = c.buildNodeTag(c.info)

	// add limiter
	l := c.server.LimiterManager.Add(c.tag, c.userList, c.aliveMap, c.info.Type)
	c.limiter = l

	if c.info.Protocol.Security == "tls" {
		err = c.requestCert()
		if err != nil {
			return fmt.Errorf("request cert error: %s", err)
		}
	}
	// Add new tag
	err = c.server.AddNode(c.tag, c.info)
	if err != nil {
		return fmt.Errorf("add new node error: %s", err)
	}
	added, err := c.server.AddUsers(&vCore.AddUsersParams{
		Tag:      c.tag,
		Users:    c.userList,
		NodeInfo: c.info,
	})
	if err != nil {
		return fmt.Errorf("add users error: %s", err)
	}
	logx.Node(c.tag).WithField("user_added", added).Info("已添加新用户")
	c.startTasks(c.info)
	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	if c == nil {
		return nil
	}
	if c.server != nil && c.server.LimiterManager != nil && c.tag != "" {
		c.server.LimiterManager.Delete(c.tag)
	}
	if c.userListMonitorPeriodic != nil {
		c.userListMonitorPeriodic.Close()
		c.userListMonitorPeriodic = nil
	}
	if c.userReportPeriodic != nil {
		c.userReportPeriodic.Close()
		c.userReportPeriodic = nil
	}
	if c.renewCertPeriodic != nil {
		c.renewCertPeriodic.Close()
		c.renewCertPeriodic = nil
	}
	if c.onlineIpReportPeriodic != nil {
		c.onlineIpReportPeriodic.Close()
		c.onlineIpReportPeriodic = nil
	}
	if c.server == nil || c.tag == "" {
		return nil
	}
	err := c.server.DelNode(c.tag)
	if err != nil {
		return fmt.Errorf("del node error: %s", err)
	}
	c.tag = ""
	return nil
}

func (c *Controller) buildNodeTag(node *panel.NodeInfo) string {
	return fmt.Sprintf("[%s]-%s:%d", c.apiClient.APIHost, node.Type, node.Id)
}
