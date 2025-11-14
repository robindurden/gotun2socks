# gotun2socks

gotun2socks 是一个使用 Golang 编写的 tun2socks 实现，既可以作为库嵌入到其他程序，也提供了完整的 CLI 工具。它通过创建 TUN/TAP 设备截获 IP 包，在用户态重建 TCP/UDP 通道并转发到本地 SOCKS5 代理，使得系统透明地借助代理访问网络。

> English TL;DR: A Golang implementation of tun2socks with both library and binary, working on Linux/macOS/Windows.

## 项目亮点

- **跨平台**：核心逻辑统一，针对 Linux/macOS/Windows 提供独立的 TUN 封装。
- **TCP/UDP 全量支持**：TCP 采用完整状态机复刻；UDP 通过 SOCKS5 UDP Associate，实现包括 DNS 在内的协议转发。
- **轻量依赖**：只依赖 gosocks、miekg/dns 等少量第三方库，方便学习和定制。
- **中文注释 & 文档**：核心模块均补充了中文注释，本文档也介绍了主要概念，便于快速理解。

## 环境要求

- Go 1.21 及以上（依赖 go.mod 中的模块版本）。
- 具备管理员权限以创建 TUN/TAP 设备。
- Windows 需要提前安装 TAP-Windows 驱动；Linux/macOS 需确保 `tun` 模块可用。

## 快速开始

### 1. 获取代码

```bash
git clone https://github.com/robin/gotun2socks.git
cd gotun2socks
```

### 2. 构建 CLI

```bash
go build -o gotun2socks ./bin/gotun2socks
```

macOS/Linux 用户需要使用 `sudo` 运行二进制以创建 TUN 设备，Windows 用户请在管理员 PowerShell 中执行。

### 3. 运行示例

```bash
sudo ./gotun2socks \
  -tun-device tun0 \
  -tun-address 10.0.0.2 \
  -tun-mask 255.255.255.0 \
  -tun-gw 10.0.0.1 \
  -tun-dns 8.8.8.8,8.8.4.4 \
  -local-socks-addr 127.0.0.1:1080 \
  -public-only=false \
  -enable-dns-cache=true
```

程序会创建 TUN/TAP 设备并自动配置地址及（在 Windows 上）DNS。随后需要根据自身网络环境调整路由表，让需要代理的流量进入 TUN 设备，可参考 [badvpn Tun2Socks 简介](https://code.google.com/p/badvpn/wiki/tun2socks) 中的路由配置步骤。

## 参数说明

| 参数 | 说明 |
| ---- | ---- |
| `-tun-device` | TUN/TAP 设备名称（macOS/Linux 常为 `tun0`/`utun`，Windows 为 TAP 适配器名称）。 |
| `-tun-address` | 虚拟网卡 IP 地址。 |
| `-tun-mask` | 虚拟网卡子网掩码。 |
| `-tun-gw` | 虚拟网关地址；配置路由时默认网关应指向此地址。 |
| `-tun-dns` | 逗号分隔的 DNS 列表，创建设备后会依序写入（Windows 会自动写入适配器）。 |
| `-local-socks-addr` | 本地 SOCKS5 代理地址，gotun2socks 会把所有 TCP/UDP 转发给该代理。 |
| `-public-only` | 若为 `true`，仅允许目标地址为公网 IP，以防内网流量被错误代理。 |
| `-enable-dns-cache` | 开启后会使用简易内存缓存缓存 DNS 响应，减少重复查询。 |

## 工作流程概览

1. **TUN 读写**：主循环从 TUN 设备读取 IPv4 数据包，解析 TCP/UDP 头部并根据 `publicOnly` 做过滤。
2. **TCP**：每条连接维护一个状态机，模拟 SYN/SYN-ACK/ACK 三次握手、流控窗口、FIN/RST 等流程，并通过 gosocks 与本地 SOCKS5 建立 TCP 通道。
3. **UDP**：按需创建 `udpConnTrack`，使用 SOCKS5 UDP Associate 建立中继；支持 DNS 缓存以及 IP 分片。
4. **写出**：所有待写回 TUN 的包会进入统一的队列，由单个 writer goroutine 顺序写出，避免竞争。

源代码各模块均补充了中文注释，可重点阅读：

- `gotun2socks.go`：整体读写调度。
- `tcp.go`：TCP 状态机与 SOCKS 桥接。
- `udp.go`：UDP 会话、DNS 缓存及分片处理。
- `ip.go` / `mtubuf.go`：IP 分片和缓冲池辅助。

## UDP 转发注意事项

UDP 使用标准 SOCKS5 UDP Request/Reply，因此**必须**搭配支持 UDP 的 SOCKS5 代理，否则 DNS 等协议无法工作。对于 DNS 流量：

- 若启用 `-enable-dns-cache`，相同问题在 TTL 期间会直接命中本地缓存，减少往返。
- DNS 响应过大时会自动做 IP 分片，确保在 MTU 约束下正常返回。

## 常见问题

1. **TUN 设备无法创建**：请确认使用管理员权限；部分 Linux 发行版需加载 `tun` 内核模块（`modprobe tun`）。
2. **路由回环**：请确保远端 SOCKS 服务器的 IP 没有被错误地转发到 TUN，否则会导致循环。可以在设置默认路由前手动添加 `ip route add <socks_ip> via <real_gw>`。
3. **UDP 未生效**：确认 SOCKS5 服务端开启 UDP 支持（如 `sslocal` 需加 `-U`），并检查本地防火墙未拦截绑定的临时端口。

## 致谢

- https://github.com/google/gopacket
- https://github.com/ambrop72/badvpn/
- https://github.com/songgao/water
- https://github.com/FlexibleBroadband/tun-go
