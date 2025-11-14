# 01 构建与运行

本章节介绍环境要求、依赖安装、构建流程以及启动 gotun2socks 所需的路由配置原则。

## 环境要求

- Go 1.21 或更新版本（以 go.mod 为准）。
- 管理员权限：创建 TUN/TAP 设备需要 root（Linux/macOS）或管理员（Windows）。
- 可用的本地 SOCKS5 代理（TCP/UDP 均需支持）。

额外平台注意事项：

- **Windows**：需预先安装 TAP-Windows 驱动，命名需与 `-tun-device` 参数一致。
- **Linux/macOS**：确保内核已加载 `tun` 模块，可通过 `sudo modprobe tun` 激活。

## 获取依赖

仓库 vendor 由 Go Modules 管理，执行 `go mod tidy` 即可自动下载。若所在网络无法直接访问，可借助私有代理或设置 `GOPROXY`。

## 构建 CLI

```
go build -o gotun2socks ./bin/gotun2socks
```

编译完成后会生成平台对应的可执行文件。运行时需具备管理员权限，否则 TUN 设备无法创建。

## 启动示例

```
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

关键参数说明：

- `-tun-*`：指定虚拟网卡的地址、掩码与网关，需与路由配置保持一致。
- `-tun-dns`：逗号分隔的 DNS 列表。在 Windows 平台会自动写入 TUN 适配器的 DNS 配置。
- `-local-socks-addr`：本地 SOCKS5 代理地址，所有 TCP/UDP 流量均会发往此地址。
- `-public-only`：设置为 `true` 时过滤私网目标地址，防止错误代理内网资源。
- `-enable-dns-cache`：启用内存 DNS 缓存，可减少重复查询。

## 路由配置原则

1. **默认路由指向 TUN 网关**：保证大多数流量进入用户态转发链路。
2. **排除 SOCKS 服务器**：在更改默认路由之前，将 SOCKS 服务器 IP 指向物理网关，避免循环。
3. **必要时修改 DNS**：若操作系统默认 DNS 位于受限网络，应将系统 DNS 调整为 `-tun-dns` 中的可访问地址。

以 Linux 为例，可先记录原始网关 `GW_REAL`，随后执行：

```
sudo ip route add <socks_ip> via <GW_REAL>
sudo ip route add default via 10.0.0.1 dev tun0
```

Windows 用户可借助 `route add` 命令完成同样操作。

## 运行时观测

程序启动后会输出连接跟踪信息，例如当前 TCP/UDP 会话数量、DNS 缓存命中日志等，可据此判断链路是否正常。当收到终止信号（SIGINT/SIGTERM 等）时，程序会自动关闭所有连接并释放 TUN 设备。

## 进一步阅读

下一章节将剖析 TCP 数据平面的内部实现，详见 [02_tcp_pipeline.md](02_tcp_pipeline.md)。
