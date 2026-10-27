// Command gateway 是 TCP 多协议网关的入口。
//
// 用法:
//
//	tcp-protocol-gateway -config config.yaml
//
// 处理 SIGINT/SIGTERM 触发优雅退出：停止接收新连接、
// 等待活跃连接结束（最长 10 秒），随后强制清理并退出。
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tcp-protocol-gateway/internal/config"
	"tcp-protocol-gateway/internal/gateway"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("tcp-protocol-gateway 1.0.0")
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.Logging.Level)
	slog.SetDefault(logger)

	srv, err := gateway.New(cfg, logger)
	if err != nil {
		logger.Error("create gateway", "error", err)
		os.Exit(1)
	}

	// 信号驱动的优雅退出。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		logger.Info("shutdown signal received, draining connections...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Warn("graceful shutdown finished with timeout", "error", err)
		}
	}()

	logger.Info("tcp-protocol-gateway starting",
		"config", *configPath,
		"listen", cfg.Server.Listen,
		"minecraft_enabled", cfg.Minecraft.Enabled)

	err = srv.ListenAndServe()
	if err == gateway.ErrServerClosed {
		logger.Info("gateway exited cleanly")
		return
	}
	if err != nil {
		logger.Error("gateway exited with error", "error", err)
		os.Exit(1)
	}
}

// newLogger 根据配置级别构造 slog Logger（文本输出到 stderr）。
func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
