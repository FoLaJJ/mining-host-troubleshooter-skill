# Mining Host Troubleshooter

[English README](README.en.md)

用于生产环境 Linux 主机挖矿入侵排查与溯源的技能包。目标很直接：在尽量不破坏现场、不影响业务的前提下，完成只读调查、现场还原、证据归档和分层报告输出。

## 适用场景

- 你怀疑 Linux 主机被植入 CPU 挖矿、GPU 挖矿或混合型挖矿程序。
- 你发现某个服务、启动项、容器或用户会话行为异常，但还不能确认是否为矿工伪装。
- 你需要把调查过程做得更规范，避免一上来就误杀进程、删文件、改配置。
- 你希望最终拿到的是可复核、可追踪、可继续扩展的案件包，而不是一堆零散命令输出。

## 使用前提与边界

在真实环境使用前，建议先看完下面几条：

- 只用于你有权检查的主机、容器、账号和网络环境。
- 默认流程是只读调查，不会主动处置；但只读采集本身仍可能带来少量 CPU、I/O、SSH 连接日志和命令审计记录。
- 这里输出的是技术调查材料，不是法律结论、审计结论，也不是任何形式的“绝对无风险证明”。
- 结论能否成立，取决于当时的权限范围、主机可见性、日志留存情况、时间窗口和现场完整度。
- 对于业务高峰期、核心数据库、核心中间件、交易系统等高敏环境，仍应先走你自己的变更、应急或值班流程。
- 远程接入前应先确认主机身份、指纹或 `known_hosts` 信任来源。不要把“能连上”当成“目标一定正确”。

## 责任说明

这里提供的是调查流程、脚本和报告模板，不替代操作者本人的判断。

- 最终是否执行、何时执行、在什么权限下执行，由使用者自己负责。
- 是否把某条线索认定为入侵、误报、业务变更、蜜罐行为或正常高算力任务，也需要结合你自己的环境背景判断。
- 如果你跳过指纹校验、在未授权环境使用、在高风险业务时段直接上生产、或者拿不完整证据去做强结论，后果不能归到这套 skill 本身。
- 仓库内的流程、脚本和报告模板不承诺覆盖所有 Linux 发行版、所有权限模型、所有云厂商细节，也不承诺发现所有高对抗样本。
- 默认报告保留溯源字段，便于内部排查；如需对外共享，请自行评估脱敏、审批和证据披露范围。

## 解决的问题

很多“矿机排查脚本”只能告诉你“这里有个高 CPU 进程”。

这里关注的不是单点检测，而是把真正关键的问题回答清楚：

- 这台主机到底是不是被入侵，还是只是合法高算力业务？
- 可疑程序到底挂在哪一层：进程、systemd 服务、cron、容器、用户目录启动项，还是伪装路径？
- 有没有持久化、重复登录、SSH 密钥投毒、PAM / sudoers / preload 等再进入面？
- 能不能从当前证据里继续追 IP、矿池、钱包、基础设施，或者明确说明为什么追不动？
- 日志是不是完整、部分缺失、已删除、疑似被篡改？
- 哪些结论是已确认，哪些只能保持待定？

## 当前能力

目前这套流程已经能覆盖大多数日常 Linux 挖矿入侵排查场景，尤其适合下面这些情况：

- CPU 挖矿、GPU 挖矿、混合矿机排查。
- 矿工进程伪装成正常服务、正常进程名或业务路径。
- 线上业务主机需要只读优先、低扰动调查。
- 同一台主机反复出现可疑行为，需要做跨案件差异比对。
- 需要给管理层、SOC、技术复核分别提供不同层次的报告。

核心能力包括：

- 支持本机与远程主机排查。
- 支持多种接入方式：本地 shell、SSH 私钥、SSH agent、账密、跳板机、控制台。
- 远程接入时支持 `known_hosts` 或主机指纹 pinning 的信任引导。
- 默认只读采集，带超时控制、检查点和证据链校验。
- 兼容 Ubuntu、Debian、Arch 等 Linux 发行版差异。
- 能处理命令缺失、alias 包装、路径漂移、可疑二进制、部分命令不可信等情况，并优先寻找只读替代链。
- 深入检查进程、服务、启动项、shell 历史、用户目录持久化、cron、systemd、timer、preload、sudoers、PAM、容器与云侧痕迹。
- 当 `ss`、`ip`、`ps`、`journalctl`、`systemctl` 之类的命令失效时，会继续尝试 `netstat`、`lsof`、`ifconfig`、`service`、`/proc` 等替代路径，而不是单点失败。
- 当认证日志、系统日志或 journal 被删除时，会继续从 `wtmp`、`btmp`、`lastlog`、service/timer 元数据、journald/rsyslog 配置、包管理历史、shell 痕迹文件、`/proc/*/exe (deleted)` 等残留证据补线索。
- 对合法高算力任务有误报控制，不会因为 CPU / GPU 高占用就直接下入侵结论。
- 支持时间标准化、结论置信度分级、观测事实 / 推断 / 归因分层。
- 自动产出案件包、分层报告、同机基线和跨案件差异比对结果。

## 调查顺序

这里不是“想到什么查什么”，而是按固定顺序推进，这样结论更稳，报告也更能站得住：

1. 先确认案件范围。
2. 再确认目标主机身份、业务重要性和接入方式。
3. 校验 SSH 信任链或本地执行信任前提。
4. 检查权限范围、命令可信度和环境可见性。
5. 执行低影响、只读优先的证据采集。
6. 基于采集结果重建现场。
7. 标准化时间线，保留不确定性。
8. 复核持久化、启动项、服务、容器、云侧线索和初始访问痕迹。
9. 校验证据链和案件包完整性。
10. 导出管理摘要、SOC 摘要和全量报告。
11. 只有存在同机历史干净样本时，才做同机基线比对。
12. 有历史案件时，再做跨案件差异分析。
13. 最后才讨论需要审批的处置动作。

## 设计原则

这套流程更适合业务主机，原因在于边界比较清晰：

- 默认允许只读检查。
- 默认禁止自动处置。
- 所有改动类命令都必须先解释影响、风险和回滚，再等待明确审批。
- 内部排查报告默认保留 IP 等溯源字段，避免把自己排查需要的信息遮掉。
- 密码、令牌、私钥等敏感值依然会保护，不会写进报告。
- 证据不够时明确写 `inconclusive`，不会强行讲故事。
- 日志缺失、权限受限、工具可疑时，会降级而不是硬编结论。
- 默认不安装软件、不重启服务、不刷新日志、不改运行参数。

## 不适用或需要额外评估的情况

下面这些情况，不建议把它当成“单独就够用”的方案：

- 你要做的是内存取证、rootkit 深挖、eBPF 深层分析或 APT 级别高对抗调查。
- 你手上的权限太低，已经不足以看到核心进程、日志、服务、用户目录或容器上下文。
- 目标主机正处于事故扩散期，需要联动边界流量、云审计、身份系统、CI/CD、镜像仓库等外部证据。
- 你需要的是自动处置、自动隔离、自动封禁，而不是只读调查和证据整理。

## 已知限制

- 这套流程优先做主机侧只读调查，外部证据源目前仍以人工联动为主。
- 遇到日志已清空、权限受限、关键二进制被替换、容器运行时被裁剪等场景时，报告会保留不确定性，不会强行补全。
- 基线和跨案件比对只适合作为辅助判断，不能单独作为“主机正常”或“主机异常”的充分依据。
- 如果目标环境对短时命令执行、目录遍历、日志读取极其敏感，请先在相近环境演练并确认本地安全策略。

## 请勿这样使用

- 不要把报告里的“未发现直接挖矿证据”理解成“主机已经证明安全”。
- 不要跳过主机身份校验后直接连生产。
- 不要在没有业务侧确认的情况下，把高 CPU、高 GPU 或大量外联直接等同于挖矿入侵。
- 不要拿其他机器的基线去给当前机器“洗白”。
- 不要在未审批的情况下，直接根据报告去杀进程、删文件、停服务或改启动项。
- 不要把内部报告原样外发；对外共享前先做脱敏、审批和证据披露评估。

## 安装方式

### 方式 1：直接从当前仓库安装

安装到本地 Agents 运行环境：

```bash
node scripts/install-skill.mjs install --target agents --force
```

安装到其它常见目标：

```bash
node scripts/install-skill.mjs install --target codex --force
node scripts/install-skill.mjs install --target cc-switch --force
```

安装到自定义技能目录：

```bash
node scripts/install-skill.mjs install --dest /path/to/skills --name mining-host-troubleshooter --force
```

查看默认目标路径：

```bash
node scripts/install-skill.mjs print-targets
```

### 方式 2：通过 `npx` 安装

仓库已经按 npm 包方式封装。发布到 npm 或私有 registry 之后，可以这样安装：

```bash
npx mining-host-troubleshooter-skill install --target agents
```

注意：只有真正发布之后，这条 `npx` 命令才可直接使用。

## 一次排查会产出什么

默认会在当前工作目录下创建案件包，而不是把结果散落在环境目录中：

```text
reports/
`-- <host-or-ip>-<utc-timestamp>/
    |-- artifacts/
    |-- evidence/
    |   |-- evidence.raw.json
    |   `-- evidence.reviewed.auto.json
    |-- report.md
    |-- report.zh-CN.md
    |-- meta/
    |   |-- artifact_hashes.json
    |   |-- case_manifest.json
    |   |-- case_validation.json
    |   |-- scene_reconstruction.json
    |   `-- workflow_checkpoints.json
    `-- reports/
        |-- index.md
        |-- index.zh-CN.md
        |-- management-summary.md
        |-- management-summary.zh-CN.md
        |-- soc-summary.md
        `-- soc-summary.zh-CN.md
```

这样拿到的不只是“排查结果”，而是一整套可继续复核、可继续追溯、可直接交付的案件材料。

## 实际产出示意

下面这个示意来自一台已完成验证的案件包结构，公开仓库中已把主机标识替换为占位符。真实内部案件默认会保留 IP 等溯源字段，方便继续追查。

### 1. 案件索引页会告诉你先看什么

```md
# Mining Host Investigation - 案件索引

## 状态卡片
- 事件 ID：`INC-20260306-xxxxxx`
- 主机：`<HOST_IP>` (`<HOST_IP>`)
- 证据项：`65` | 研判项：`5` | 时间线：`1`
- 认证来源 IP：`1` | 监听端口：`3`

## 最新研判
- `F-AUTO-001` [观测事实/已确认/中] 认证类证据显示：共出现 1 次失败密码事件，涉及 1 个来源 IP。
- `F-AUTO-002` [观测事实/已确认/高] 监听套接字证据显示，当前涉及的端口包括：22、3307、53。
- `F-AUTO-003` [推断/已确认/低] 初始访问与高权限访问复核面返回了若干需要分析人员继续复核的记录。

## 建议阅读顺序
1. 先看 `index.zh-CN.md`
2. 再看 `management-summary.zh-CN.md` 或 `soc-summary.zh-CN.md`
3. 最后进入 `report.zh-CN.md` 深挖证据链
```

### 2. 全量报告不是原始命令堆砌，而是结构化结论

```md
## 执行摘要
- 证据项数量：`65`
- 结论状态：`5` 条已确认，`0` 条待定
- 日志完整性风险：`2` 项
- 结论类型分布：观测事实 `2`，推断 `3`，归因 `0`
- 置信度分布：🟢 高 `1`，🟡 中 `1`，🟠 低 `3`

### ✅ F-AUTO-002
- 表述：监听套接字证据显示，当前涉及的端口包括：22、3307、53。
- 结论类型：`观测事实`
- 置信度：🟢 `高`
- 状态：`已确认`
- 证据链：[E-008](./report.zh-CN.md#evidence-e-008) / [产物](artifacts/E-008.txt)
```

### 3. 证据索引可直接跳转到产物

```md
## 证据索引
| 证据ID | 采集时间 | 命令预览 | 产物 |
| --- | --- | --- | --- |
| [E-001](#evidence-e-001) | 2026-03-06T13:05:43+00:00 | date -Is; timedatectl show ... | [E-001.txt](artifacts/E-001.txt) |
| [E-008](#evidence-e-008) | 2026-03-06T13:05:46+00:00 | ss -tulpen | [E-008.txt](artifacts/E-008.txt) |
| [E-012](#evidence-e-012) | 2026-03-06T13:05:47+00:00 | journalctl -u ssh --since ... | [E-012.txt](artifacts/E-012.txt) |
```

用于真实案件时，最终交付物通常会包含：

- 一份案件索引，告诉不同角色先看什么。
- 一份管理摘要，适合快速判断风险和审批动作。
- 一份 SOC 摘要，适合值守和初筛。
- 一份全量报告，适合技术复核和证据链追踪。
- 一组可校验哈希的原始产物和结构化 evidence JSON。

## 日志缺失时还能查什么

如果攻击者删掉了 `auth.log`、`secure`、`syslog`，流程不会直接停在“日志没了”。

它会继续检查这些只读线索：

- `wtmp`、`btmp`、`lastlog` 这类登录数据库是否仍然存活。
- `journald`、`rsyslog`、`syslog-ng` 是否还在运行，配置有没有被改成降低留存或转发。
- service、timer、cron、`authorized_keys`、`rc.local`、`/etc/ld.so.preload` 这些启动面最近有没有异常变更。
- `~/.bash_history` 之外的残留痕迹，比如 `.wget-hsts`、`.lesshst`、`.viminfo`、`.python_history`。
- 包管理器历史里有没有异常安装或升级痕迹。
- `/proc/*/exe` 是否存在 `(deleted)` 的可执行文件映射。
- `ss` 不可用时是否还能从 `netstat`、`lsof`、`/proc/net/*` 看到当下连接和监听状态。

这些线索不能代替完整日志，但足够帮助你判断：

- 证据是不是被清理过。
- 攻击面更像 SSH、启动项、容器、下载执行还是计划任务。
- 哪些结论还能确认，哪些必须继续保持待定。

## 快速开始

下面示例里的 `<...>` 都是占位符，需要按你的目标主机、账号、指纹和环境信息替换。

### 1. 远程主机：SSH 私钥方式

```bash
python scripts/run_readonly_workflow.py \
  --remote <REMOTE_USER>@<HOST_IP> \
  --host-key-fingerprint "<SHA256_HOST_KEY_FINGERPRINT>" \
  --identity <SSH_KEY_PATH> \
  --analyst <ANALYST> \
  --host-ip <HOST_IP> \
  --os-hint "<OS_HINT>" \
  --mining-mode auto \
  --profile enterprise-self-audit \
  --expected-workload "<合法高算力业务说明或留空>" \
  --strict-report
```

### 2. 远程主机：账号密码方式

```bash
python scripts/run_readonly_workflow.py \
  --remote <REMOTE_USER>@<HOST_IP> \
  --host-key-fingerprint "<SHA256_HOST_KEY_FINGERPRINT>" \
  --password-env <SSH_PASSWORD_ENV> \
  --analyst <ANALYST> \
  --host-ip <HOST_IP> \
  --os-hint "<OS_HINT>" \
  --mining-mode auto \
  --profile enterprise-self-audit \
  --expected-workload "<合法高算力业务说明或留空>" \
  --strict-report
```

### 3. 本机只读排查

```bash
python scripts/run_readonly_workflow.py \
  --analyst <ANALYST> \
  --host-name <HOST_NAME> \
  --host-ip <HOST_IP> \
  --os-hint "<OS_HINT>" \
  --mining-mode auto \
  --profile enterprise-self-audit \
  --expected-workload "<合法高算力业务说明或留空>" \
  --strict-report
```

如果是第一次在你自己的环境使用，建议先在低风险测试机或影子环境跑一遍，再上业务主机。

## 推荐使用顺序

如果想把这套流程用完整，建议按下面顺序使用：

1. 需要快速检查环境时，先跑 `scripts/preflight_environment.py`。
2. 主要调查时，优先跑 `scripts/run_readonly_workflow.py`。
3. 先看 `reports/<case>/reports/index.zh-CN.md`，确认案件包状态与报告入口。
4. 给管理层看 `management-summary.zh-CN.md`，给值守或分析人员看 `soc-summary.zh-CN.md`。
5. 做技术定性、复核证据链和追溯产物时，再进入 `report.zh-CN.md`。
6. 只有存在同机历史干净样本时，才接入基线。
7. 如果这台主机以前也有案子，再跑跨案件差异比对。

## 典型场景

- 线上 Linux 主机 CPU 飙高，同时伴随异常外联。
- GPU 矿机算力异常、拒绝率上升、miner 频繁崩溃，但需要先排除被入侵。
- 某个服务名称看起来正常，实际启动路径或参数非常可疑。
- 云主机或容器宿主机可能被滥用元数据凭据、恶意镜像或逃逸链路植入矿工。
- 日志已经缺失，需要靠替代证据和只读路径尽量还原现场。
- 同一台主机多次出现异常，需要做“旧案 vs 新案”的差异分析。

## 报告结构

这里输出的是分层报告，而不是一份又长又乱的原始命令拼接。

- `index.*`：案件入口页，告诉你先看什么。
- `management-summary.*`：管理层摘要，适合快速决策。
- `soc-summary.*`：SOC 分诊视图，适合值守和初筛。
- `report.*`：全量报告，适合技术复核和取证细查。

全量报告会明确区分：

- 观测事实
- 推断
- 归因
- 置信度与置信度原因
- 标准化时间线
- 已溯源与未溯源 IP
- 日志完整性风险
- 审批门控动作记录
- 可点击跳转的证据 ID 与产物链接

## 同机基线与历史案件比对

基线类型必须严格区分：

- 同机干净基线：只能用于同一台主机的历史对比、噪声抑制和漂移观察。
- 同角色参考画像：只能给分析人员提供“这类主机通常长什么样”的参考，不能当作另一台主机的清白证明，也不能自动压制告警。

类似的云主机、蜜罐节点、主控端或被控端，只能作为参考画像素材，不能直接合并成“同机干净基线”。

注意：如果基线只来自单次虚拟机快照、单个案件，或者样本太少，它就只能算弱基线。弱基线绝不能作为“机器没问题”的证据，只能作为后续持续丰富的起点。正确做法是随着同一台主机的更多已知干净案件不断补充，让基线质量逐步提升。

生成同机干净基线：

```bash
python scripts/generate_host_baseline.py \
  --reports-root reports \
  --host-ip <HOST_IP>
```

在新案件中应用基线：

只有在你明确知道这是同一台主机的历史基线时，才应该传入 `--baseline`。如果你手里只有其他相似业务机的案件材料，请把它们当作人工参考，不要当成自动对照标准。


```bash
python scripts/run_readonly_workflow.py \
  --remote <REMOTE_USER>@<HOST_IP> \
  --identity <SSH_KEY_PATH> \
  --analyst <ANALYST> \
  --host-ip <HOST_IP> \
  --os-hint "<OS_HINT>" \
  --mining-mode auto \
  --profile enterprise-self-audit \
  --baseline reports/_baselines/<HOST_IP>-baseline-<timestamp>/baseline.json \
  --strict-report
```

做跨案件差异比对：

```bash
python scripts/compare_case_bundles.py \
  --base-case reports/<older-case> \
  --target-case reports/<newer-case>
```

## 安全边界

默认允许的只有只读检查。

下面这些动作必须先得到明确审批：

- 杀进程
- 停服务
- 删除、截断、移动文件
- 改配置、改启动项
- 重启或中断业务
- 任何可能破坏证据或改变主机状态的动作

## 发布或重装前校验

```bash
python C:/Users/admin/.codex/skills/.system/skill-creator/scripts/quick_validate.py D:/skills/mining-host-troubleshooter-skill
python scripts/audit_example_placeholders.py --strict
```

## 仓库说明

- `README.md` 是中文入口，`README.en.md` 是英文入口。
- `SKILL.md` 是运行时遵循的核心契约。
- `references/` 存放详细排查手册与降级说明。
- `scripts/` 存放可执行工作流和辅助工具。

如果你的目标是做 Linux 业务主机上的只读挖矿排查、现场还原和证据归档，可以从这里的默认流程开始，再按自己的环境继续补充基线、外部证据接口和内部审批要求。


