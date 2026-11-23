// Command ssht 启动 SSH 端口转发管理服务
package main

import (
	"flag"
	"log"

	"github.com/zngw/ssht/internal/server"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "HTTP 监听地址")
	dataPath := flag.String("data", "ssht.dat", "加密数据文件路径")
	flag.Parse()

	if err := server.Run(*addr, *dataPath); err != nil {
		log.Fatal(err)
	}
}
