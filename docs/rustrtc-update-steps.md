# rustrtc 更新步骤文档

日期: 2026-03-13

关联文档:
- `docs/rustrtc-audit-2026-03-13.md`
- `docs/rustrtc-issue-task-checklist.md`
- `docs/rustrtc-security-hardening-plan.md`
- `docs/rustrtc-webrtc-gap-matrix.md`
- `docs/rustrtc-webrtc-completion-plan.md`

目的:
- 将安全加固计划与 WebRTC 能力差距矩阵整合成一份可执行的更新步骤文档
- 明确哪些工作必须先做，哪些工作可以并行，哪些工作属于后续扩展
- 为 issue 拆分、里程碑规划和回归验收提供统一依据

适用范围:
- WebRTC 主路径
- 安全硬化
- 协议行为对齐
- 媒体能力补齐
- 工程化收尾

## 1. 当前基线

当前已经具备的能力:

- 自研 `PeerConnection`、SDP、ICE/STUN/TURN、DTLS、SRTP、SCTP/DataChannel、RTP/RTCP 主路径
- 常规 Offer/Answer、re-invite、simulcast ingest、direct RTP/SRTP mode
- DTLS fingerprint 绑定校验闭环
- `cargo check`
- `cargo check --tests --examples`

当前仍然阻碍项目成为完整生产级 WebRTC 终止栈的关键缺口:

1. SRTP / SRTCP replay protection 不完整
2. DTLS / DataChannel 分片与重组缺少硬上限
3. `pranswer/rollback` 未实现
4. codec 运行时模型过薄，`fmtp/rtcp-fb` 没有进入真正协商闭环
5. `RtcConfiguration.certificates` 未接线
6. DataChannel 默认语义与浏览器默认行为不一致
7. TURN/TCP/TLS 路径与 candidate 语义尚未收敛
8. 视频默认收发 codec 能力不对齐
9. stats 公开类型与实际产出不一致

## 2. 更新原则

1. 先补安全闭环，再补能力扩展
2. 先补浏览器互通关键路径，再补复杂网络和高级 codec
3. 先消除“看起来支持、实际上未落地”的配置/API，再扩大公开能力面
4. 每一步都必须配套最小回归测试
5. 每个阶段结束时都要能给出可验证的完成标准

## 3. 总体阶段划分

### 阶段 A: 安全基线补齐

目标:
- 让公网环境下最容易出问题的安全短板先闭环

包含事项:
1. SRTP / SRTCP replay protection
2. DTLS / DataChannel 分片与重组上限
3. 安全专项回归测试

阶段出口:
- 重放攻击和缓冲膨胀问题不再是主阻断项

### 阶段 B: WebRTC 规范关键路径补齐

目标:
- 让主流浏览器互通不再依赖“碰巧走通”

包含事项:
1. `pranswer/rollback`
2. codec runtime model
3. `fmtp/rtcp-fb` runtime negotiation
4. `RtcConfiguration.certificates` 接线
5. DataChannel 默认行为修正
6. 收敛 `bundle_policy` / `IceCredentialType::Oauth` 等错位 API

阶段出口:
- 规范关键状态机和默认行为基本对齐

### 阶段 C: 复杂网络与媒体链路补齐

目标:
- 让受限网络、复杂 codec 和自适应媒体路径达到可用状态

包含事项:
1. TURN/TCP/TLS 修正
2. 是否实现 ICE-TCP 的明确决策
3. VP8/H264 默认能力对齐
4. REMB/TWCC 闭环
5. VP9 / H.265 扩展

阶段出口:
- 在复杂网络和多 codec 条件下具备稳定行为

### 阶段 D: 工程化收尾

目标:
- 让文档、统计、回归和配置说明足以支撑持续迭代

包含事项:
1. Stats 能力补齐
2. 安全和互操作指标可观测
3. CI 或准 CI 回归矩阵
4. 文档和配置说明收尾

阶段出口:
- 项目不再只是“能实现”，而是“可维护地演进”

## 4. 分步骤更新方案

### 步骤 1: 建立统一回归底座

目标:
- 在修改安全和协商逻辑前，先固定已有正确行为

要做的事:
1. 保留并扩展 `fingerprint mismatch` 负向测试
2. 为当前可用的 Offer/Answer、re-invite、ordered channel、TURN relay 建立基线回归组
3. 将安全类测试与功能类测试分组，便于后续追踪

输出:
- 一组可反复运行的最小回归集合

依赖:
- 无

### 步骤 2: 补齐 SRTP / SRTCP replay protection

目标:
- 消除 SRTP/SRTCP 的核心安全缺口

要做的事:
1. 为 RTP 引入标准 replay window
2. 为 SRTCP 引入独立 replay window
3. 对重复包、过旧包和窗口外包做明确拒绝
4. 将 replay reject 结果纳入日志和统计

建议修改位置:
- `src/srtp.rs`

验收标准:
- 重复包被拒绝
- 窗口内乱序包可接受
- 过旧包被拒绝
- RTP 与 SRTCP 都具备对应保护

### 步骤 3: 为 DTLS / DataChannel 重组增加硬上限

目标:
- 消除最直接的内存型 DoS 面

要做的事:
1. 为 DTLS handshake 分片重组增加累计字节上限
2. 为 DTLS 分片数或消息长度增加限制
3. 为 DataChannel 单消息重组增加字节上限
4. 为单 channel 重组缓冲增加限制
5. 明确超限后的行为: 丢弃、关闭 channel 或失败退出

建议修改位置:
- `src/transports/dtls/mod.rs`
- `src/transports/sctp.rs`
- `src/transports/datachannel.rs`
- `src/config.rs`

验收标准:
- 超限输入不会导致缓冲无限增长
- 超限路径可观测
- 正常消息不回归

### 步骤 4: 补齐 `pranswer/rollback`

目标:
- 补上完整 signaling 状态机中的明确缺口

要做的事:
1. 定义 `stable/have-local-offer/have-remote-offer` 下的 rollback 规则
2. 为本地和远端 description 增加 rollback 路径
3. 为 `pranswer -> answer` 增加合法状态迁移
4. 明确异常状态返回值

建议修改位置:
- `src/peer_connection.rs`
- 必要时 `src/sdp.rs`

验收标准:
- rollback 后可重新发起协商
- `pranswer -> answer` 可走通
- 常规 Offer/Answer 和 re-invite 不回归

依赖:
- 建议在步骤 1 之后进行

### 步骤 5: 重构 codec 运行时模型

目标:
- 让协商结果真正进入运行时，而不是只停留在 SDP 文本层

要做的事:
1. 扩展 `RtpCodecParameters`
2. 增加 `codec_name`
3. 增加 `fmtp`
4. 增加 `rtcp_fbs`
5. 按 payload type 合并 `rtpmap/fmtp/rtcp-fb`
6. 在生成 answer 时真正做本地能力与远端能力交集

建议修改位置:
- `src/peer_connection.rs`
- `src/config.rs`
- 如有必要新增 `src/media/codecs.rs`

验收标准:
- Opus `fmtp` 能进入运行时
- H264 `packetization-mode/profile-level-id` 不丢失
- 不兼容 codec 组合会被拒绝或正确降级

依赖:
- 这是后续 VP8/VP9/H264/H.265 对齐和扩展的前置条件

### 步骤 6: 修正证书配置与默认 DataChannel 语义

目标:
- 解决两个最容易误导使用者的运行时行为问题

要做的事:
1. 让 `RtcConfiguration.certificates` 真正进入运行时
2. 在未配置证书时继续保留自签回退
3. 配置证书后重算本地 fingerprint
4. 将 DataChannel 默认值从 `ordered=false` 调整为 `ordered=true`
5. 校验 DCEP `channel_type` 与默认行为一致

建议修改位置:
- `src/config.rs`
- `src/peer_connection.rs`
- `src/transports/dtls/mod.rs`
- `src/transports/datachannel.rs`
- `src/transports/sctp.rs`

验收标准:
- 配置证书后实际使用配置证书
- 错误证书配置会明确失败
- `create_data_channel(label, None)` 表现为 ordered reliable
- 显式 `ordered=false` 不回归

### 步骤 7: 收敛 API 与实现错位

目标:
- 消除“配置存在但实现不成立”的工程噪音

要做的事:
1. 明确 `IceCredentialType::Oauth` 是实现还是提前报错
2. 明确 `bundle_policy` 是真正实现还是文档收敛
3. 检查其它仅停留在配置层的字段是否需要降级处理

建议修改位置:
- `src/config.rs`
- `src/peer_connection.rs`
- `src/transports/ice/turn.rs`

验收标准:
- 用户不会再通过公开配置误判支持范围

依赖:
- 可与步骤 6 并行

### 步骤 8: 修正 TURN/TCP/TLS，并明确 ICE-TCP 策略

目标:
- 让复杂网络回退路径具备明确、真实的支持边界

要做的事:
1. 保证 TURN over TCP/TLS 可用
2. 修正 `probe_stun()` 的 TCP 伪实现
3. 修正 relay candidate `transport` 语义
4. 增加 `turn:?transport=tcp` 与 `turns:` 测试
5. 明确是否实现 ICE-TCP

决策建议:
1. 如果近期目标是浏览器公网互通，优先完成 TURN/TCP/TLS
2. 如果目标包含企业内网 TCP 直连，再启动 ICE-TCP

若选择实现 ICE-TCP:
1. 为 candidate 增加 `tcptype`
2. 扩展 SDP `to_sdp()/from_sdp()`
3. 增加 TCP host candidate gather
4. 增加 TCP connectivity check

建议修改位置:
- `src/transports/ice/mod.rs`
- `src/transports/ice/turn.rs`
- `src/sdp.rs`

验收标准:
- 仅依赖 TURN/TCP/TLS 时仍可建连
- 不会再出现 server transport 与 candidate transport 语义错位

### 步骤 9: 补齐媒体默认链路与拥塞控制闭环

目标:
- 让默认视频能力和控制反馈从“半实现”变成“可用闭环”

要做的事:
1. 补 `VP8 depacketizer`
2. 对齐默认发送与接收的视频 codec 组合
3. 明确 H264 默认能力是否保留
4. 将 REMB 从“只解析”推进到实际控制
5. 将 TWCC 从“报文结构存在”推进到完整闭环

建议修改位置:
- `src/media/depacketizer.rs`
- `src/media/packetizer.rs`
- `src/config.rs`
- `src/peer_connection.rs`
- `src/rtp.rs`

验收标准:
- VP8 默认视频双向收发通过
- H264 若保留能力广告，则存在对应收发链路
- REMB/TWCC 能影响发送侧行为，而不是只打印日志

依赖:
- 建议在步骤 5 完成后推进

### 步骤 10: 增加 VP9 / H.265 扩展

目标:
- 在现有链路收敛后，再增加现代视频 codec

要做的事:
1. 为 `VP9` 增加 `rtpmap/fmtp` 协商与收发链路
2. 为 `H.265` 增加显式启用开关
3. 新增 `Vp9Payloader` / `Vp9Depacketizer`
4. 新增 `H265Payloader` / `H265Depacketizer`
5. 按协商结果动态选择 depacketizer
6. 明确 fallback:
   - `VP9` 回退到 `VP8/H264`
   - `H.265` 只在显式启用且对端支持时启用

建议修改位置:
- `src/config.rs`
- `src/peer_connection.rs`
- `src/media/packetizer.rs`
- `src/media/depacketizer.rs`
- 如实现复杂度上升，可新增 `src/media/vp9.rs`
- 如实现复杂度上升，可新增 `src/media/h265.rs`

验收标准:
- `VP9 only`
- `H.265 only`
- `VP8 + VP9` fallback
- `H264 + H.265` fallback
- reinvite 中 codec 切换不回归

依赖:
- 必须在步骤 5 基本完成后推进

### 步骤 11: 补齐 stats、观测与文档收尾

目标:
- 让系统具备可维护性和上线后的排障能力

要做的事:
1. 产出 `Transport` stats
2. 产出 `IceCandidatePair` stats
3. 产出 `DataChannel` stats
4. 补齐 RTT 等未完成统计
5. 增加安全与异常事件计数:
   - fingerprint mismatch
   - SRTP replay reject
   - SRTCP replay reject
   - DTLS 重组超限
   - DataChannel 重组超限
   - TURN 认证失败
6. 更新文档，使其与实现范围保持一致

建议修改位置:
- `src/stats.rs`
- `src/stats_collector.rs`
- 相关 transport / srtp / datachannel 模块
- `docs/`

验收标准:
- stats 类型与实际产出一致
- 关键异常路径可通过统计观测
- 文档不再出现配置声明与运行时能力错位

## 5. 并行关系与依赖顺序

建议严格按以下依赖推进:

1. 步骤 1
2. 步骤 2 和 步骤 3
3. 步骤 4
4. 步骤 5
5. 步骤 6 和 步骤 7
6. 步骤 8
7. 步骤 9
8. 步骤 10
9. 步骤 11

可并行部分:

- 步骤 2 与 步骤 3
- 步骤 6 与 步骤 7
- 步骤 11 中的文档整理可与后期开发并行

不建议提前做的项:

- 在步骤 5 之前推进 `VP9 / H.265`
- 在步骤 8 尚未收敛前承诺 `ICE-TCP`
- 在步骤 2 和步骤 3 之前宣称项目具备公网试运行条件

## 6. 最小验收矩阵

浏览器互通最小矩阵:

1. Chrome:
   - 音频
   - 视频
   - DataChannel
   - re-invite
   - ICE restart
   - TURN/UDP
   - TURN/TCP
   - TURN/TLS
2. Firefox:
   - 音频
   - 视频
   - DataChannel
   - re-invite
   - ICE restart
   - TURN/UDP
   - TURN/TCP
   - TURN/TLS

负向与安全矩阵:

1. fingerprint mismatch
2. oversized DTLS fragment
3. oversized DataChannel message
4. SRTP replay
5. SRTCP replay
6. rollback
7. `pranswer -> answer`
8. TURN 错误凭据
9. 异常 ICE candidate 输入

codec 矩阵:

1. Opus
2. VP8
3. H264
4. VP9
5. H.265
6. codec fallback

## 7. 建议的 issue 拆分

建议直接按以下工作包拆任务:

1. `baseline/regression-safety-net`
2. `security/srtp-replay-window`
3. `security/dtls-sctp-buffer-limits`
4. `signaling/pranswer-rollback`
5. `media/codec-runtime-model`
6. `config/certificate-plumbing`
7. `interop/datachannel-default-ordering`
8. `config/remove-misleading-api-surface`
9. `network/turn-tcp-tls-fix`
10. `network/ice-tcp-decision`
11. `media/default-video-path-alignment`
12. `cc/remb-twcc-closure`
13. `media/vp9-support`
14. `media/h265-support`
15. `stats/transport-and-datachannel`
16. `ops/security-observability`
17. `docs/implementation-scope-sync`

## 8. 里程碑完成定义

### 可考虑公网试运行

至少同时满足:

1. 步骤 2 完成
2. 步骤 3 完成
3. 步骤 4 完成
4. 步骤 6 完成
5. 至少一组安全负向测试进入固定回归

### 可称为“浏览器级可用主路径”

至少同时满足:

1. 步骤 5 完成
2. 步骤 8 完成
3. 步骤 9 完成
4. Chrome / Firefox 主路径互通通过

### 可称为“具备持续维护条件”

至少同时满足:

1. 步骤 11 完成
2. issue 和文档同步维护
3. 公开 API 与实现边界一致

## 9. 结论

`rustrtc` 当前最需要的不是继续扩 API，而是把已经存在的协议栈能力收敛成可靠、可验证、可维护的实现。

更新顺序上，应优先保证:

1. 安全闭环
2. 规范关键路径
3. 网络与媒体复杂场景
4. 高级 codec 扩展
5. 工程化收尾

只有按这个顺序推进，后续 `VP9 / H.265`、复杂网络回退和更大规模互操作测试才不会建立在不稳定基线上。
