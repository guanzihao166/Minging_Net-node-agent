package cmd

import (
	"github.com/perfect-panel/ppanel-node/common/logx"

	"github.com/spf13/cobra"
)

var command = &cobra.Command{
	Use: "ppnode",
}

func Run() {
	err := command.Execute()
	if err != nil {
		logx.Component("server").WithError(err).Error("执行命令失败")
	}
}
