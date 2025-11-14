# 02 TCP 数据通道

本章节围绕 `tcp.go` 展开，说明 Tun2Socks 如何在用户态复刻 TCP 状态机并与 SOCKS5 代理互操作。

## 关键结构

- `tcpPacket`：封装 IPv4/TCP 头与缓冲区，配合对象池减少分配。
- `tcpConnTrack`：每条 TCP 连接对应一个实例，负责状态机、窗口管理、与 SOCKS 交互。
- `writeCh`：统一写回 TUN 的通道，由 `gotun2socks.go` 的 writer goroutine 顺序处理。

连接由 4 元组 `<src_ip, src_port, dst_ip, dst_port>` 标识，并存储在 `tcpConnTrackMap` 中。

## 状态机流程

1. **CLOSED**：收到 SYN 时尝试连接本地 SOCKS，并向内核回 SYN/ACK；若 SOCKS 连接失败则立即 RST。
2. **SYN_RCVD**：等待合法 ACK。若成功则进入 ESTABLISHED，同时启动 `tcpSocks2Tun` 协程，负责代理流量读写。
3. **ESTABLISHED**：处理常规数据包，校验序列号与窗口。若收到 FIN，则回复 FIN/ACK 并迁移到 LAST_ACK。
4. **FIN_WAIT_1 / FIN_WAIT_2 / CLOSING / LAST_ACK / TIME_WAIT**：覆盖四次挥手过程中所有合法分支，并在状态完成后清理连接。

整个过程中需要维护 `nxtSeq`（发送序列）、`rcvNxtSeq`（期望接收序列）与 `recvWindow` / `sendWindow`，以模拟内核 TCP 行为。

## 与 SOCKS5 的交互

当状态进入 ESTABLISHED 后，`tcpSocks2Tun` 完成以下职责：

1. 发送 SOCKS `CONNECT` 请求，目标地址使用原始 IP/端口。
2. 建立两个方向的协程：
   - **SOCKS → TUN**：读取代理端返回的数据，根据发送窗口拆分为 `tcpPacket`，通过 `payload()` 写回 TUN。
   - **TUN → SOCKS**：收到内核发来的带数据包时，放入 `toSocksCh` 写入 SOCKS 连接，并根据数据量调整 `recvWindow`。
3. 当检测到 SOCKS 连接关闭或发生错误时，触发 FIN/ACK，进入挥手阶段。

## 流控与重传

- `sendWindow` 根据对端报文中的 Window 值动态调整。若窗口耗尽，SOCKS 读取协程会等待 `sendWndCond`。
- `recvWindow` 表示仍可接受的字节数。每次将数据转发给 SOCKS 后会减少，等代理确认写入后再增加。
- 当收到不符合 `rcvNxtSeq` 的报文时，立即发送 ACK 请求重传，从而维持可靠性。

## 错误处理

- 非期望状态下的 RST 会直接终止连接。
- 如果收到非 SYN 的初始报文，则生成 RST 防止半开连接。
- 正常或异常结束都会关闭 SOCKS 连接、停止相关 goroutine，并从 `tcpConnTrackMap` 中删除记录。

## 进一步阅读

若已理解 TCP 数据平面，可继续查看 [03_udp_and_dns.md](03_udp_and_dns.md)，了解 UDP 与 DNS 缓存实现。
