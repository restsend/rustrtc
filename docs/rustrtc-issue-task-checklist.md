# rustrtc issue/task 清单与自动化验证方案

日期: 2026-03-13

关联文档:
- `docs/rustrtc-update-steps.md`
- `docs/rustrtc-audit-2026-03-13.md`
- `docs/rustrtc-security-hardening-plan.md`
- `docs/rustrtc-webrtc-gap-matrix.md`
- `docs/rustrtc-webrtc-completion-plan.md`

目标:
- 将 `docs/rustrtc-update-steps.md` 拆成可直接进入 issue 或任务系统的工作清单
- 为每个工作项补齐自动化测试方案
- 明确哪些项可复用现有测试，哪些项需要新增专门的测试客户端或测试 harness

原则:
1. 每个任务必须至少对应一个自动化验证入口
2. 每个高风险协议改动必须同时包含正向测试和负向测试
3. 每个跨栈能力至少保留一个本地可跑的互操作测试
4. 优先复用现有 `tests/` 和 `examples/`，不足部分再补专门测试客户端
5. 每个步骤在“建议命令”全部通过后，必须生成 `git commit memo` 并提交，未提交视为未完成

## 1. 自动化验证分层

建议将自动化验证固定分成五层:

### L0: 编译与静态门禁

- `cargo check`
- `cargo check --tests --examples`

用途:
- 防止 API 改动和测试入口失效

### L1: 单元与组件测试

运行方式:
- `cargo test --lib`
- `cargo test --test <name>`

用途:
- 验证纯协议逻辑、状态机分支、包解析、重放窗口、缓冲上限

### L2: 本地互操作测试

运行方式:
- 现有 `webrtc-rs` 集成测试
- 本地 loopback peer
- 本地 TURN server / 本地 helper client

用途:
- 验证跨栈语义而不是只测内部函数

### L3: 专门测试客户端

适用场景:
- 需要构造异常报文
- 需要生成特定 codec 协商组合
- 需要验证 TURN/TCP/TLS、TWCC、VP9/H.265 之类当前仓内缺少现成对端的场景

建议增加的测试客户端目录:

1. `tests/clients/webrtc_rs_peer/`
2. `tests/clients/pion_peer/`
3. `tests/clients/local_turn_server/`
4. `tests/clients/rtcp_feedback_peer/`
5. `tests/clients/malformed_peer/`

说明:
- `webrtc-rs` 适合 DataChannel、Offer/Answer、TURN、基础媒体互通
- `Pion` 更适合做 codec 扩展、复杂 SDP 组合和更贴近浏览器的互操作补充
- `malformed_peer` 用于发非法 DTLS/SCTP/RTP/ICE 输入，不依赖真实浏览器

### L4: commit memo 与提交门禁

适用范围:
- 本文中的每一个 `ISSUE-xx`

规则:
1. 只有在该步骤列出的“建议命令”全部通过后，才允许生成 commit
2. commit 前必须先生成一份 `git commit memo`
3. commit memo 至少要覆盖:
   - `Issue`
   - `变更摘要`
   - `涉及模块/文件`
   - `自动测试命令`
   - `测试结果`
   - `风险与后续事项`
4. commit message 应直接吸收该 memo 的核心信息，而不是只写一句模糊标题
5. 如果某步骤依赖专门测试客户端，该客户端验证结果也必须写入 memo

建议模板:

```text
<short subject>

Issue: ISSUE-xx <name>
Summary:
- ...

Files:
- ...

Verification:
- cargo test ...
- cargo test ...

Result:
- pass

Risk:
- ...

Follow-up:
- ...
```

提交要求:
- 每个步骤的“完成门禁”都默认包含这一层
- 未生成 memo 或未提交 commit，不应将该步骤标记为完成

## 2. 建议复用的现有测试资产

当前可直接复用:

1. `src/transports/dtls/tests.rs`
   - DTLS 主路径
   - fingerprint mismatch
2. `tests/ordered_channel_test.rs`
   - ordered channel
   - DCEP ordered path
3. `tests/interop_datachannel.rs`
   - webrtc-rs 与 RustRTC DataChannel 互操作
4. `tests/interop_turn.rs`
   - TURN relay 路径
5. `tests/interop_simulcast.rs`
   - simulcast ingest 与 RID/SelectorTrack
6. `tests/rtp_reinvite_test.rs`
7. `tests/rtp_reinvite_comprehensive_test.rs`
   - reinvite 相关路径
8. `tests/sctp_reliability.rs`
9. `tests/sctp_congestion_control_test.rs`
   - SCTP 可靠性和拥塞控制
10. `tests/media_flow.rs`
   - 基础媒体收发

## 3. issue/task 清单

通用说明:
- 以下每个 `ISSUE` 除了各自列出的“完成门禁”，还必须满足上面的 `L4: commit memo 与提交门禁`
- 也就是说，单纯“测试跑通”还不算完成，必须在测试跑通后生成 commit memo 并提交

### ISSUE-01 `baseline/regression-safety-net`

目标:
- 建立后续所有协议改动都要经过的统一自动化底座

任务:
1. 建立按能力分组的测试入口:
   - `security`
   - `signaling`
   - `datachannel`
   - `network`
   - `media`
   - `stats`
2. 将现有关键测试纳入固定分组
3. 补一个统一测试脚本或 CI job 映射表

自动测试方案:
- 复用:
  - `src/transports/dtls/tests.rs`
  - `tests/ordered_channel_test.rs`
  - `tests/interop_datachannel.rs`
  - `tests/interop_turn.rs`
  - `tests/rtp_reinvite_comprehensive_test.rs`
- 新增:
  - `tests/regression_baseline.rs`
    - 只负责检查关键能力入口没有被误删

建议命令:
- `cargo check`
- `cargo check --tests --examples`
- `cargo test --test ordered_channel_test`
- `cargo test --test interop_datachannel`
- `cargo test --test interop_turn`
- `cargo test --test rtp_reinvite_comprehensive_test`

专门客户端需求:
- 无

完成门禁:
- 关键主路径测试可以按分组稳定运行

### ISSUE-02 `security/srtp-replay-window`

目标:
- 补齐 SRTP / SRTCP replay protection

任务:
1. 为 RTP 增加 replay window
2. 为 SRTCP 增加 replay window
3. 为重复包、过旧包、乱序包定义明确处理结果
4. 将 reject 事件输出到统计和日志

自动测试方案:
- 新增单元测试:
  - `tests/srtp_replay_window.rs`
    - `duplicate_rtp_packet_rejected`
    - `out_of_order_rtp_packet_within_window_accepted`
    - `too_old_rtp_packet_rejected`
    - `duplicate_srtcp_packet_rejected`
- 新增组件测试:
  - `tests/srtp_replay_integration.rs`
    - 建立两个本地 SRTP 上下文
    - 注入重复包与乱序包
    - 验证发送侧和接收侧行为

建议命令:
- `cargo test --test srtp_replay_window`
- `cargo test --test srtp_replay_integration`

专门客户端需求:
- 无
- 使用本地 packet fixture 即可

完成门禁:
- RTP/SRTCP replay 正向与负向测试全部通过

### ISSUE-03 `security/dtls-sctp-buffer-limits`

目标:
- 为 DTLS 和 DataChannel 重组链路增加硬上限

任务:
1. 为 DTLS handshake 分片重组增加大小上限
2. 为 DataChannel 单消息重组增加大小上限
3. 为单 channel 重组缓冲增加上限
4. 明确超限时的关闭或丢弃策略

自动测试方案:
- 新增单元测试:
  - `src/transports/dtls/tests.rs`
    - `test_dtls_fragment_reassembly_rejects_oversized_message`
  - `tests/datachannel_reassembly_limits.rs`
    - `oversized_ordered_message_rejected`
    - `oversized_unordered_message_rejected`
    - `near_limit_message_accepted`
- 新增异常输入测试:
  - `tests/security_malformed_buffers.rs`

专门客户端需求:
- 需要新增 `tests/clients/malformed_peer/`
- 功能:
  - 直接发送伪造 DTLS fragment
  - 直接发送伪造 SCTP/DataChannel fragment
- 原因:
  - 这类非法输入不适合依赖浏览器或 `webrtc-rs` 生成

建议命令:
- `cargo test dtls_fragment_reassembly_rejects_oversized_message`
- `cargo test --test datachannel_reassembly_limits`
- `cargo test --test security_malformed_buffers`

完成门禁:
- 超限输入稳定失败
- 接近阈值的正常输入不回归

### ISSUE-04 `signaling/pranswer-rollback`

目标:
- 补齐 `pranswer/rollback`

任务:
1. 实现本地 rollback
2. 实现远端 rollback
3. 实现 `pranswer -> answer`
4. 补齐异常状态分支

自动测试方案:
- 新增测试:
  - `tests/signaling_pranswer_rollback.rs`
    - `local_rollback_restores_stable`
    - `remote_rollback_restores_stable`
    - `pranswer_then_answer_succeeds`
    - `invalid_state_rejected`
- 扩展现有测试:
  - `tests/rtp_reinvite_test.rs`
  - `tests/rtp_reinvite_comprehensive_test.rs`

专门客户端需求:
- 首轮不需要
- 若要验证跨栈兼容性，可在第二阶段补 `tests/clients/webrtc_rs_peer/`

建议命令:
- `cargo test --test signaling_pranswer_rollback`
- `cargo test --test rtp_reinvite_test`
- `cargo test --test rtp_reinvite_comprehensive_test`

完成门禁:
- 所有 signaling 状态迁移均有自动测试覆盖

### ISSUE-05 `media/codec-runtime-model`

目标:
- 将 codec 协商结果引入运行时

任务:
1. 扩展 `RtpCodecParameters`
2. 解析 `rtpmap/fmtp/rtcp-fb`
3. 在 answer 生成时做能力交集
4. 为后续 VP9/H.265 保留 codec-specific 参数结构

自动测试方案:
- 新增单元测试:
  - `tests/codec_runtime_model.rs`
    - `extract_payload_map_preserves_codec_name`
    - `extract_payload_map_preserves_fmtp`
    - `extract_payload_map_preserves_rtcp_fb`
    - `answer_rejects_incompatible_codec_pair`
- 新增集成测试:
  - `tests/codec_negotiation_integration.rs`
    - `opus_fmtp_roundtrip`
    - `h264_profile_level_id_roundtrip`
    - `h264_packetization_mode_roundtrip`

专门客户端需求:
- 建议新增 `tests/clients/pion_peer/`
- 用途:
  - 生成更复杂的 H264/VP9/H.265 SDP 组合
  - 避免只依赖当前 `webrtc-rs` 的 codec 覆盖面

建议命令:
- `cargo test --test codec_runtime_model`
- `cargo test --test codec_negotiation_integration`

完成门禁:
- Opus/H264 的关键 `fmtp` 参数进入运行时

### ISSUE-06 `config/certificate-plumbing`

目标:
- 让 `RtcConfiguration.certificates` 真正进入运行时

任务:
1. 支持从 PEM 链和私钥加载证书
2. 未配置证书时保留自签
3. 配置证书后重算 fingerprint
4. 明确错误配置的失败路径

自动测试方案:
- 新增单元测试:
  - `tests/certificate_config.rs`
    - `pem_certificate_load_success`
    - `pem_key_mismatch_fails`
    - `default_self_signed_fallback_works`
- 新增集成测试:
  - `tests/certificate_fingerprint_integration.rs`
    - 配置固定证书
    - 生成 SDP
    - 校验 fingerprint 与证书一致

专门客户端需求:
- 无
- 可本地生成临时 PEM fixture

建议命令:
- `cargo test --test certificate_config`
- `cargo test --test certificate_fingerprint_integration`

完成门禁:
- 配置证书路径和默认路径均可自动验证

### ISSUE-07 `interop/datachannel-default-ordering`

目标:
- 让默认 DataChannel 语义与浏览器一致

任务:
1. 将默认值改为 `ordered=true`
2. 校验 DCEP `channel_type`
3. 保持显式 `ordered=false` 可用

自动测试方案:
- 扩展现有测试:
  - `tests/ordered_channel_test.rs`
    - 增加 `create_data_channel(label, None)` 默认行为断言
- 新增测试:
  - `tests/datachannel_default_semantics.rs`
    - `default_channel_is_ordered_reliable`
    - `explicit_unordered_still_supported`

专门客户端需求:
- 复用现有 `webrtc-rs` 对端即可

建议命令:
- `cargo test --test ordered_channel_test`
- `cargo test --test datachannel_default_semantics`

完成门禁:
- 默认 `None` 配置的跨栈行为与浏览器语义一致

### ISSUE-08 `config/remove-misleading-api-surface`

目标:
- 消除配置与实现错位

任务:
1. `IceCredentialType::Oauth` 明确为实现或提前报错
2. `bundle_policy` 明确为实现或行为收敛
3. 审核其它仅停留在配置层的字段

自动测试方案:
- 新增测试:
  - `tests/config_support_matrix.rs`
    - `oauth_credential_fails_early_with_clear_error`
    - `bundle_policy_behavior_is_explicit`
    - `unsupported_config_is_not_silently_ignored`

专门客户端需求:
- 无

建议命令:
- `cargo test --test config_support_matrix`

完成门禁:
- 不再存在“静默接受但运行时无效”的配置入口

### ISSUE-09 `network/turn-tcp-tls-fix`

目标:
- 修正 TURN/TCP/TLS 和 candidate transport 语义

任务:
1. 修正 `probe_stun()` 的 TCP 伪实现
2. 修正 relay candidate transport 语义
3. 打通 TURN over TCP/TLS
4. 增加 `turn:?transport=tcp` 和 `turns:` 回归测试

自动测试方案:
- 扩展:
  - `tests/interop_turn.rs`
- 新增:
  - `tests/interop_turn_tcp.rs`
  - `tests/interop_turn_tls.rs`
  - `tests/turn_candidate_semantics.rs`

专门客户端需求:
- 需要新增 `tests/clients/local_turn_server/`
- 功能:
  - 在测试进程内或辅助进程里启动本地 TURN server
  - 支持 UDP/TCP/TLS 三种入口
- 说明:
  - 这样可避免依赖外部 TURN 环境

建议命令:
- `cargo test --test interop_turn`
- `cargo test --test interop_turn_tcp`
- `cargo test --test interop_turn_tls`
- `cargo test --test turn_candidate_semantics`

完成门禁:
- 仅依赖本地 TURN/TCP/TLS 也可完成建连和 DataChannel 互通

### ISSUE-10 `network/ice-tcp-decision`

目标:
- 明确是否实现 ICE-TCP，并让该结论可自动验证

任务 A: 如果决定暂不实现
1. 在配置、日志和文档中明确声明不支持
2. 对 TCP candidate 输入提前报错或安全忽略

任务 B: 如果决定实现
1. 增加 `tcptype`
2. 扩展 SDP 解析与生成
3. 增加 TCP host candidate gather
4. 增加 TCP connectivity check

自动测试方案:
- 若暂不实现:
  - `tests/ice_tcp_not_supported.rs`
    - `tcp_candidate_rejected_with_clear_error`
    - `tcp_candidate_does_not_trigger_invalid_udp_logic`
- 若实现:
  - `tests/ice_tcp_connectivity.rs`
  - `tests/ice_tcp_sdp_roundtrip.rs`

专门客户端需求:
- 若暂不实现: 无
- 若实现: 需要新增 `tests/clients/tcp_candidate_peer/`

建议命令:
- `cargo test --test ice_tcp_not_supported`
- 或
- `cargo test --test ice_tcp_connectivity`
- `cargo test --test ice_tcp_sdp_roundtrip`

完成门禁:
- 不支持时有清晰自动验证
- 支持时有完整 TCP 建连回归

### ISSUE-11 `media/default-video-path-alignment`

目标:
- 对齐默认视频 codec 收发链路

任务:
1. 增加 `VP8 depacketizer`
2. 明确默认视频能力集
3. 保证广告与实际收发链路一致

自动测试方案:
- 新增单元测试:
  - `tests/vp8_depacketizer.rs`
- 新增集成测试:
  - `tests/video_default_path.rs`
    - `vp8_send_receive_roundtrip`
    - `h264_advertised_path_has_receiver`

专门客户端需求:
- 建议复用 `webrtc-rs` 或 `Pion`
- 若 `webrtc-rs` 的视频能力不足，优先用 `Pion` helper

建议命令:
- `cargo test --test vp8_depacketizer`
- `cargo test --test video_default_path`

完成门禁:
- 默认视频能力不再出现“协商成功但媒体解不开”的假成功

### ISSUE-12 `cc/remb-twcc-closure`

目标:
- 让 REMB/TWCC 从报文层实现推进到控制闭环

任务:
1. 收到 REMB 后更新发送侧目标码率
2. 为 TWCC 引入序列号写入、反馈生成和带宽估计
3. 将估计结果作用到 sender

自动测试方案:
- 新增单元测试:
  - `tests/remb_controller.rs`
  - `tests/twcc_feedback.rs`
- 新增集成测试:
  - `tests/congestion_control_integration.rs`
    - 模拟不同反馈强度
    - 验证目标码率变化

专门客户端需求:
- 需要新增 `tests/clients/rtcp_feedback_peer/`
- 功能:
  - 精确构造 REMB 和 TWCC 反馈
  - 记录 RustRTC 的码率调整结果

建议命令:
- `cargo test --test remb_controller`
- `cargo test --test twcc_feedback`
- `cargo test --test congestion_control_integration`

完成门禁:
- 反馈到控制行为形成可测闭环

### ISSUE-13 `media/vp9-support`

目标:
- 增加 VP9 协商和收发链路

任务:
1. 增加 `VP9` SDP 协商
2. 增加 `Vp9Payloader`
3. 增加 `Vp9Depacketizer`
4. 验证与 simulcast / reinvite 的兼容性

自动测试方案:
- 新增单元测试:
  - `tests/vp9_packetizer.rs`
  - `tests/vp9_depacketizer.rs`
- 新增协商测试:
  - `tests/vp9_negotiation.rs`
- 新增集成测试:
  - `tests/vp9_media_flow.rs`

专门客户端需求:
- 需要新增 `tests/clients/pion_peer/`
- 原因:
  - `Pion` 更适合作为 VP9 对端

建议命令:
- `cargo test --test vp9_packetizer`
- `cargo test --test vp9_depacketizer`
- `cargo test --test vp9_negotiation`
- `cargo test --test vp9_media_flow`

完成门禁:
- `VP9 only` 和 `VP8 + VP9 fallback` 可自动验证

### ISSUE-14 `media/h265-support`

目标:
- 增加 H.265 显式启用、协商、收发和回退

任务:
1. 增加 H.265 协商
2. 增加 `H265Payloader`
3. 增加 `H265Depacketizer`
4. 增加显式启用开关
5. 验证 fallback

自动测试方案:
- 新增单元测试:
  - `tests/h265_packetizer.rs`
  - `tests/h265_depacketizer.rs`
- 新增协商测试:
  - `tests/h265_negotiation.rs`
- 新增集成测试:
  - `tests/h265_media_flow.rs`
  - `tests/h265_fallback.rs`

专门客户端需求:
- 需要新增 `tests/clients/pion_peer/`
- 说明:
  - H.265 支持矩阵更碎片化，不建议只依赖仓内假对端

建议命令:
- `cargo test --test h265_packetizer`
- `cargo test --test h265_depacketizer`
- `cargo test --test h265_negotiation`
- `cargo test --test h265_media_flow`
- `cargo test --test h265_fallback`

完成门禁:
- 显式启用才广告 H.265
- `H264 + H.265 fallback` 可自动验证

### ISSUE-15 `stats/transport-and-datachannel`

目标:
- 让 stats 类型与实际产出一致

任务:
1. 增加 `Transport` stats
2. 增加 `IceCandidatePair` stats
3. 增加 `DataChannel` stats
4. 补 RTT 等未完成字段

自动测试方案:
- 新增测试:
  - `tests/stats_transport.rs`
  - `tests/stats_datachannel.rs`
  - `tests/stats_ice_candidate_pair.rs`
- 扩展:
  - `src/stats_collector.rs` 现有测试

专门客户端需求:
- 无
- 复用本地 peer 和现有 DataChannel / TURN 测试即可触发统计

建议命令:
- `cargo test --test stats_transport`
- `cargo test --test stats_datachannel`
- `cargo test --test stats_ice_candidate_pair`

完成门禁:
- `StatsKind` 暴露的关键类型均有真实产出

### ISSUE-16 `ops/security-observability`

目标:
- 为安全和异常路径增加可观测性

任务:
1. 增加 replay reject 计数
2. 增加 fingerprint mismatch 计数
3. 增加 DTLS/DataChannel 重组超限计数
4. 增加 TURN 认证失败计数

自动测试方案:
- 新增测试:
  - `tests/security_metrics.rs`
    - 每个异常路径触发一次
    - 校验计数器或 stats entry 增长

专门客户端需求:
- 可复用:
  - `malformed_peer`
  - `local_turn_server`

建议命令:
- `cargo test --test security_metrics`

完成门禁:
- 关键异常路径都能被自动触发并观测到

### ISSUE-17 `docs/implementation-scope-sync`

目标:
- 保持文档、配置和测试事实一致

任务:
1. 每次关闭 issue 时同步更新:
   - 审计文档
   - gap matrix
   - update steps
   - completion plan
2. 记录该能力的自动测试入口
3. 如果能力只在特定模式下成立，必须写明

自动测试方案:
- 新增轻量脚本:
  - `scripts/check-doc-links.sh`
  - 检查核心文档是否都引用最新 checklist
- 新增文档一致性测试:
  - `tests/doc_scope_smoke.rs`
  - 检查关键未实现项不会被误标为已实现

专门客户端需求:
- 无

建议命令:
- `bash scripts/check-doc-links.sh`
- `cargo test --test doc_scope_smoke`

完成门禁:
- 文档不再长期落后于实现

## 4. 推荐的专门测试客户端设计

### 4.1 `tests/clients/malformed_peer/`

用途:
- 发送异常 DTLS/SCTP/DataChannel/ICE 输入

覆盖任务:
- ISSUE-03
- ISSUE-16

建议实现:
- Rust
- 直接复用仓内报文结构和 socket 抽象

### 4.2 `tests/clients/local_turn_server/`

用途:
- 在本地测试中启动 TURN UDP/TCP/TLS 服务

覆盖任务:
- ISSUE-09
- ISSUE-16

建议实现:
- Rust
- 优先复用现有 `turn` 依赖或测试内 helper

### 4.3 `tests/clients/rtcp_feedback_peer/`

用途:
- 精确发送 REMB/TWCC/PLI/FIR/NACK 反馈

覆盖任务:
- ISSUE-12
- ISSUE-15

建议实现:
- Rust
- 方便与现有 `rtp.rs` 报文结构复用

### 4.4 `tests/clients/pion_peer/`

用途:
- 做 VP9/H.265 和复杂 SDP 互操作

覆盖任务:
- ISSUE-05
- ISSUE-11
- ISSUE-13
- ISSUE-14

建议实现:
- Go
- 参考现有 `examples/interop_pion_go/`

### 4.5 `tests/clients/webrtc_rs_peer/`

用途:
- 做默认浏览器语义近似验证
- 覆盖 DataChannel、基础媒体、TURN 主路径

覆盖任务:
- ISSUE-04
- ISSUE-07
- ISSUE-09
- ISSUE-15

建议实现:
- Rust
- 直接复用当前 `tests/interop_*.rs` 里的公共逻辑

## 5. 建议的 CI 分组

### CI-1 `check`

- `cargo check`
- `cargo check --tests --examples`

### CI-2 `security`

- ISSUE-02
- ISSUE-03
- ISSUE-16

### CI-3 `signaling-and-datachannel`

- ISSUE-04
- ISSUE-07
- ISSUE-08

### CI-4 `network`

- ISSUE-09
- ISSUE-10

### CI-5 `media-core`

- ISSUE-05
- ISSUE-11
- ISSUE-12

### CI-6 `media-extended`

- ISSUE-13
- ISSUE-14

### CI-7 `stats-and-docs`

- ISSUE-15
- ISSUE-17

说明:
- `media-extended` 可先作为非阻断 job，等 VP9/H.265 落地后转为阻断
- `network` 中的 TURN/TLS 若依赖本地证书，可在 CI 内动态生成

## 6. 交付顺序建议

按可执行性建议按以下顺序建 issue:

1. ISSUE-01
2. ISSUE-02
3. ISSUE-03
4. ISSUE-04
5. ISSUE-05
6. ISSUE-06
7. ISSUE-07
8. ISSUE-08
9. ISSUE-09
10. ISSUE-10
11. ISSUE-11
12. ISSUE-12
13. ISSUE-15
14. ISSUE-16
15. ISSUE-13
16. ISSUE-14
17. ISSUE-17

说明:
- `stats` 和 `observability` 可以在媒体扩展前完成
- `VP9 / H.265` 必须排在 codec runtime model 之后

## 7. 完成定义

只有当以下条件满足，才能说这份 checklist 执行完成:

1. 每个 issue 都有对应自动化测试入口
2. 每个高风险改动都有负向测试
3. 每个跨栈能力都有至少一个本地互操作验证
4. 外部依赖场景都有本地 helper client 或本地 server 替代
5. CI 能按分组稳定执行这些测试

这样，`rustrtc` 的后续演进才不会再依赖手工验证或临时经验判断。
