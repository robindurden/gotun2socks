# 03 UDP 与 DNS

本章节描述 UDP 会话如何通过 SOCKS5 转发，以及 DNS 缓存与 IP 分片的实现方式。

## UDP 会话生命周期

- 每个 UDP 会话由 `udpConnTrack` 表示，内部保存本地/远端 IP、端口以及 SOCKS 连接。
- 通过 `udpConnID` 组合 4 元组以复用现有会话，若不存在则新建并立即启动 `run()` 循环。
- `run()` 负责：
  1. 与 SOCKS5 建立 TCP 连接，并发送 `UDP ASSOCIATE` 请求获知中继地址。
  2. 在本地绑定 UDP 端口，将来自 TUN 的请求封装为 SOCKS UDP 数据报并发送。
  3. 监听中继返回的 UDP 包，解析后写回 TUN。
  4. 根据 DNS 或普通会话设置不同的超时时间（DNS：10 秒；其他：2 分钟）。

当 TUN 侧或 SOCKS 侧任一路径关闭时，会话立即清理并退出。

## 数据封装与分片

- `responsePacket()` 根据请求的源/目的信息组装 IPv4 + UDP 响应，并在必要时触发 IP 分片。
- 若 payload 大于 `MTU-28`，会把剩余部分交给 `genFragments()`，由 writer 依次写回。
- `udpPacketPool` 与缓冲区池共同减少内存分配。

## DNS 缓存

- 当启用 `-enable-dns-cache` 时，`dnsCache` 会在 UDP 模块内初始化。
- 对于目的端口 53 且目标 IP 在 `-tun-dns` 列表中的请求，会先查询缓存：若命中，直接构造响应写回 TUN，省略 SOCKS 链路。
- `cache.store()` 仅缓存 `RcodeSuccess` 且存在 Answer 的响应，过期时间取第一条 Answer 的 TTL。
- 缓存命中时会记录耗时日志，便于评估性能。

## 错误与超时处理

- 如果 SOCKS 连接或本地 UDP 套接字创建失败，将关闭会话并从 `udpConnTrackMap` 中删除。
- 遇到 `gosocks.UDPReader` 退出、SOCKS 连接断开或超时，会立即清理资源并通知上层。
- `quitByOther` 用于全局控制，例如 Tun2Socks 停止服务时强制结束所有会话。

## 下一步

至此已完成对 TCP/UDP 流程的逐步解析。参考源代码中的中文注释，可进一步研究 `internal/packet`、`tun` 等模块的实现细节，或根据需求扩展额外功能。
