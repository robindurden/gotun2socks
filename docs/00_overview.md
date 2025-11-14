# 00 总览

本章节用于快速了解 gotun2socks 的目标、整体结构以及关键依赖，为后续深入阅读奠定基础。

## 项目标的

gotun2socks 以 Golang 实现 tun2socks 思路，在用户态读取 TUN/TAP 设备的 IPv4 包，并将 TCP/UDP 会话映射到本地 SOCKS5 代理。该方案使宿主机上任意进程无需额外配置即可透明使用代理服务，常用于穿透受限网络环境。

## 代码结构概览

```
.
├── bin/gotun2socks      # CLI 入口
├── gotun2socks.go       # 读写循环、连接追踪调度
├── tcp.go               # TCP 状态机与 SOCKS 桥接
├── udp.go               # UDP 转发、DNS 缓存
├── ip.go / mtubuf.go    # IP 分片及缓冲池工具
├── tun/                 # 各平台 TUN/TAP 封装
└── internal/packet      # IPv4/TCP/UDP 解析与序列化
```

其中 `gotun2socks.go` 负责协调读写循环；`tcp.go`、`udp.go` 则维护协议状态并与 SOCKS5 通信；`tun` 目录根据操作系统差异提供具体实现。

## 数据通路

1. CLI 入口根据参数打开 TUN 设备，并传入 `Tun2Socks` 对象。
2. Reader goroutine 从 TUN 读取数据包，根据协议类型交给 TCP 或 UDP 模块。
3. 各协议模块维护连接追踪，负责与 SOCKS 代理交互，并准备回写数据。
4. Writer goroutine 统一从 `writeCh` 取出数据包写回 TUN，保持发送顺序。

## 主要依赖

- `github.com/yinghuocho/gosocks`：SOCKS5 协议实现，提供 TCP connect 与 UDP associate。
- `github.com/miekg/dns`：DNS 报文解析与序列化，供缓存模块使用。
- `golang.org/x/sys` 等：提供跨平台系统调用能力。

## 进一步阅读

下一章节将讲解如何搭建环境、编译并运行 gotun2socks，可参考 [01_build_and_run.md](01_build_and_run.md)。
