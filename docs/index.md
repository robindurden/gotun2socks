# gotun2socks 文档索引

本目录将 gotun2socks 的核心知识拆分为若干阶段，按照序号依次阅读即可从整体架构逐步深入到具体协议实现。

| 序号 | 文档 | 摘要 |
| ---- | ---- | ---- |
| 00 | [00_overview.md](00_overview.md) | 描述项目目标、整体结构以及主要依赖，帮助建立宏观理解。 |
| 01 | [01_build_and_run.md](01_build_and_run.md) | 说明环境要求、构建步骤、运行示例与路由配置要点。 |
| 02 | [02_tcp_pipeline.md](02_tcp_pipeline.md) | 深入解析 TCP 连接追踪、状态机以及与 SOCKS5 代理的交互流程。 |
| 03 | [03_udp_and_dns.md](03_udp_and_dns.md) | 介绍 UDP 代理链路、DNS 缓存及 IP 分片策略。 |

阅读完全部章节后，可结合源代码中的中文注释进行进一步探索。
