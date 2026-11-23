package server

import (
	"context"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Run 启动 HTTP 服务并阻塞, 直到服务出错或收到退出信号
func Run(addr, dataPath string) error {
	staticFS, err := fs.Sub(embedFS, "static")
	if err != nil {
		return err
	}

	app := NewApp(dataPath, templateFuncs())

	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", app.handleLoginGet)
	mux.HandleFunc("POST /login", app.handleLoginPost)
	mux.HandleFunc("POST /logout", app.handleLogout)
	mux.HandleFunc("POST /reset", app.handleReset)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	mux.HandleFunc("GET /{$}", app.requireAuth(app.handleForwards))
	mux.HandleFunc("POST /forward/save", app.requireAuth(app.handleForwardSave))
	mux.HandleFunc("POST /forward/delete", app.requireAuth(app.handleForwardDelete))
	mux.HandleFunc("POST /forward/connect", app.requireAuth(app.handleForwardConnect))
	mux.HandleFunc("POST /forward/disconnect", app.requireAuth(app.handleForwardDisconnect))
	mux.HandleFunc("POST /forward/batch", app.requireAuth(app.handleForwardBatch))
	mux.HandleFunc("GET /keys", app.requireAuth(app.handleKeys))
	mux.HandleFunc("POST /key/save", app.requireAuth(app.handleKeySave))
	mux.HandleFunc("POST /key/delete", app.requireAuth(app.handleKeyDelete))
	mux.HandleFunc("GET /password", app.requireAuth(app.handlePasswordPage))
	mux.HandleFunc("POST /password/change", app.requireAuth(app.handlePasswordChange))
	mux.HandleFunc("GET /api/status", app.requireAuth(app.handleStatus))

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("SSH 端口转发管理已启动: http://%s (数据文件: %s)", addr, dataPath)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		return err
	case <-stop:
		log.Println("正在关闭...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		app.stopAll()
		log.Println("已退出")
		return nil
	}
}
