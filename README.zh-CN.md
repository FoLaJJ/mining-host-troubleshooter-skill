# Mining Host Troubleshooter

[English README](README.md)

一套面向生产环境 Linux 主机的挖矿入侵排查与溯源技能，核心目标是：在尽量不破坏现场、不影响业务的前提下，完成只读调查、现场还原、证据归档和分层报告输出。

这个仓库适合以下场景：

- 你怀疑 Linux 主机被植入 CPU 挖矿、GPU 挖矿或混合型挖矿程序。
- 你发现某个服务、启动项、容器或用户会话行为异常，但还不能确认是否为矿工伪装。
- 你需要把调查过程做得更规范，避免一上来就误杀进程、删文件、改配置。
- 你希望最终拿到的是可复核、可追踪、可继续扩展的案件包，而不是一堆零散命令输出。

## 为什么值得安装

很多所谓的“矿机排查脚本”只能告诉你“这里有个高 CPU 进程”。

这个 skill 的重点不是只做检测，而是帮助你把真正关键的问题回答清楚：

- 这台主机到底是不是被入侵，还是只是合法高算力业务？
- 可疑程序到底挂在哪一层：进程、systemd 服务、cron、容器、用户目录启动项，还是伪装路径？
- 有没有持久化、重复登录、SSH 密钥投毒、PAM / sudoers / preload 等再进入面？
- 能不能从当前证据里继续追 IP、矿池、钱包、基础设施，或者明确说明为什么追不动？
- 日志是不是完整、部分缺失、已删除、疑似被篡改？
- 哪些结论是已确认，哪些只能保持待定？

## 当前能力与成果

这套 skill 目前已经能覆盖大多数日常 Linux 挖矿入侵排查场景，尤其适合下面这些情况：

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
- 能处理命令缺失、alias 包装、路径漂移、可疑二进制、部分命令不可信等情况。
- 深入检查进程、服务、启动项、shell 历史、用户目录持久化、cron、systemd、preload、sudoers、PAM、容器与云侧痕迹。
- 对合法高算力任务有误报控制，不会因为 CPU / GPU 高占用就直接下入侵结论。
- 支持时间标准化、结论置信度分级、观测事实 / 推断 / 归因分层。
- 自动产出案件包、分层报告、同机基线和跨案件差异比对结果。

## 调查顺序

这套 skill 不是“想到什么查什么”，而是按固定顺序推进，这样结论更稳、报告更能站得住：

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

这套 skill 很适合业务主机，原因就在于它的边界比较清晰：

- 默认允许只读检查。
- 默认禁止自动处置。
- 所有改动类命令都必须先解释影响、风险和回滚，再等待明确审批。
- 内部排查报告默认保留 IP 等溯源字段，避免把自己排查需要的信息遮掉。
- 密码、令牌、私钥等敏感值依然会保护，不会写进报告。
- 证据不够时明确写 `inconclusive`，不会强行讲故事。
- 日志缺失、权限受限、工具可疑时，会降级而不是硬编结论。

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

这个仓库已经按 npm 包的方式做了封装。发布到 npm 或私有 registry 之后，可以这样安装：

```bash
npx mining-host-troubleshooter-skill install --target agents
```

注意：只有真正发布之后，这条 `npx` 命令才可直接使用。

## 一次排查会产出什么

默认情况下，skill 会在当前工作目录下创建案件包，而不是把结果散落在环境目录中：

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

这意味着你拿到的不只是“排查结果”，而是一整套可继续复核、可继续追溯、可直接交付的案件材料。

## 快速开始

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

## 推荐使用顺序

如果你想让这套 skill 发挥出完整效果，建议按下面顺序使用：

1. 需要快速检查环境时，先跑 `scripts/preflight_environment.py`。
2. 主要调查时，优先跑 `scripts/run_readonly_workflow.py`。
3. 先看 `reports/<case>/reports/index.zh-CN.md`，确认案件包状态与报告入口。
4. 给管理层看 `management-summary.zh-CN.md`，给值守或分析人员看 `soc-summary.zh-CN.md`。
5. 做技术定性、复核证据链和追 artifact 时，再进入 `report.zh-CN.md`。
6. 只有存在同机历史干净样本时，才接入 baseline。
7. 如果这台主机以前也有案子，再跑跨案件差异比对。

## 典型场景

- 线上 Linux 主机 CPU 飙高，同时伴随异常外联。
- GPU 矿机算力异常、拒绝率上升、miner 频繁崩溃，但需要先排除被入侵。
- 某个服务名称看起来正常，实际启动路径或参数非常可疑。
- 云主机或容器宿主机可能被滥用元数据凭据、恶意镜像或逃逸链路植入矿工。
- 日志已经缺失，需要靠替代证据和只读路径尽量还原现场。
- 同一台主机多次出现异常，需要做“旧案 vs 新案”的差异分析。

## 报告为什么有价值

这套 skill 输出的是分层报告，而不是一份又长又乱的原始命令拼接。

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
- 可点击跳转的证据 ID 与 artifact 链接

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
python C:/Users/admin/.codex/skills/.system/skill-creator/scripts/quick_validate.py D:/skills/mining-host-troubleshooter
python scripts/audit_example_placeholders.py --strict
```

## 仓库说明

- `README.md` 和 `README.zh-CN.md` 是给人看的安装与评估文档。
- `SKILL.md` 是给 agent 执行时遵循的核心契约。
- `references/` 存放详细排查手册与降级说明。
- `scripts/` 存放可执行工作流和辅助工具。

如果你想要的是一套真正适合 Linux 业务主机、默认只读、注重现场还原、强调证据链、还能直接导出分层报告的挖矿排查技能，这个仓库已经具备比较完整的落地能力。


