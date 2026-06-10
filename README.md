# Mining Host Troubleshooter

用于 Linux 主机疑似入侵、挖矿木马、持久化与本地提权暴露面的只读排查与溯源技能。

这个仓库是一个 **skill**，不是给用户手工拼脚本参数的命令集合。正常使用方式是让大模型调用 skill，skill 再自动编排脚本执行与报告导出。

## 核心定位

- 最小破坏：默认只读，优先保现场。
- 证据驱动：先采集证据，再输出结论。
- 结论分级：区分观测事实、推断、归因，并给出置信度。
- 主结论保守：主结论必须有证据链，弱线索保留为待证实线索，不得强行升格。
- 范围可指定：可单独指定查入侵、查挖矿、查木马、查持久化、查提权暴露面。
- 审批门禁：任何状态变更操作必须先得到明确确认，而且默认不进入处置阶段。

## 适用场景

- Linux 主机出现异常 CPU/GPU 占用，怀疑挖矿或伪装挖矿。
- 只想单独确认“是否被入侵、攻击者做了什么、植入了什么木马”。
- 只想单独确认“是否存在 sudo / CopyFail / DirtyFrag 等本地提权暴露面”，但仍然坚持只读取证。
- 可疑服务、启动项、计划任务、容器行为需要追根溯源。
- 业务主机需要低扰动、可追溯的只读排查流程。
- 日志缺失或被清理，需要通过残留证据尽量还原现场。

## 如何使用（面向 skill 调用）

直接在对话中调用 skill，不需要手工运行脚本：

- `$mining-host-troubleshooter 排查 <HOST_IP>，账号 <REMOTE_USER>，密码 <PASSWORD>，重点看 GPU 挖矿`
- `$mining-host-troubleshooter 本机疑似挖矿，先做只读排查并导出中文报告`
- `$mining-host-troubleshooter 对这台机器做跨案件差异比对，并输出结论置信度`
- `$mining-host-troubleshooter 只排查这台机器有没有被入侵、攻击者进来后做了什么，默认只读`
- `$mining-host-troubleshooter 只排查挖矿木马、矿池、钱包、启动项和落地文件，默认只读`
- `$mining-host-troubleshooter 只排查 sudo / CopyFail / DirtyFrag 等本地提权暴露面，默认只读，不做利用验证`

你可以继续用自然语言追加控制条件，例如：

- “先不要执行任何变更操作，只做只读取证。”
- “如果要 kill/stop/delete，先告诉我影响和回滚方案，再等我确认。”
- “报告里保留可溯源 IP，不要隐藏。”
- “先只查是否被入侵，不要扩展到处置。”
- “先只查提权暴露面和本地提权痕迹，不要做任何验证性利用。”

## 根据现有证据补生成报告

这个模式是**显式模式**，只有使用者明确表达“根据现有证据生成报告”“补生成报告”“不要重新采集，直接出报告”这类意图时，skill 才允许走这条路径。

默认命令是：

```bash
python scripts/generate_reports_from_bundle.py --case-dir .
```

补生成规则：

- `--case-dir` 默认就是当前目录，要求这里已经是一个已有案件目录。
- 只会使用当前案件目录 `evidence/` 下已有的证据继续生成报告，不会重新登录主机，也不会重新采集。
- 即使当前目录里已经有 `artifacts/`、`evidence/`、`meta/`，普通“排查”“检查是否入侵”“收集证据”这类请求也**不能**自动切到补生成模式，仍然必须先走正常采集流程。
- 如果只是已有证据导出被中断，补生成模式会重建整套固定报告产物，而不是只补单个文件。

## 技能内部排查流程

1. **Trust Bootstrap**：确认目标身份、校验 SSH 信任链（`known_hosts`/指纹）。
2. **Distro First**：先识别发行版、内核、包管理器、当前权限，明确 Ubuntu / Debian / CentOS / RHEL / Rocky / Alma 等差异。
3. **Readonly Sweep**：执行低影响只读采集，带超时、检查点、降级兜底。
   - 远程认证链路默认保守降级：遇到口令失败或 host key 不匹配立即停止，不做盲重试。
   - 只有在非认证类问题（如 shell/channel 兼容性）时，才允许极少量单次降级尝试。
4. **Deep Evidence Correlation**：关联进程、网络、持久化、容器、云线索、GPU 进程映射、本地提权暴露面、微小配置差异。
5. **Second-Pass Self-Review**：在出报告前强制复核时间线质量、范围闭环、发行版日志布局、误报风险和外部补证支点。
6. **Confidence-Gated Conclusion**：按证据完整度输出 `confirmed` 或 `inconclusive`，禁止杜撰。
7. **Approval-Gated Response**：仅输出处置建议，变更操作必须显式审批。

固定自动化顺序是：

`collect -> enrich -> review -> validate -> export`

## 关键自动解析能力

- 自动提取高 CPU 进程并映射到对应可执行程序（PID -> exe -> cmdline）。
- 自动解析矿工类命令参数：`algorithm`、`pool`、`proxy`、`wallet`、`password`、`cpu-threads`。
- 自动提取 systemd `ExecStart`、cron/crontab 调度中的可疑运行命令画像。
- GPU 侧采用多路径只读探测，不依赖单一 `nvidia-smi`，会结合 `lspci`、`lshw`、`/dev/dri`、`/sys/class/drm`、`/proc/driver/nvidia`、`rocm-smi` 等线索。
- 自动识别命令不可用/降级标记，并在报告中显式给出可见性边界。
- 自动记录离线/受限环境线索，明确说明本技能不依赖 GitHub 下载额外工具，也不会主动尝试外部下载。
- 远程连接失败时仍会在当前案件目录内落 `failure bundle`、简报、外部补证清单和主报告，不允许因为一条登录链路失败就什么都不产出。
- 自动做跨来源矛盾与欺骗风险复核，关注认证痕迹、主日志、journald、`wtmp/btmp`、命令解析路径之间是否互相打架。
- 自动把“主结论”和“待证实线索”分层，要求关键结论绑定 `evidence_ids`，并把缺日志、命令污染、漏洞暴露分别与“已被利用/已被清理”拆开描述。
- 对向日葵、ToDesk、AnyDesk、RustDesk、TeamViewer 这类双用途远控工具默认做中性记录：先记录存在、运行和启动方式，再判断是否有未授权使用证据。
- 优先识别 Linux 发行版、内核版本、sudo/关键包版本，先知道证据应该放在哪里、应该怎么看。
- 日志缺失时自动转向 `wtmp`、`btmp`、`lastlog`、journald/rsyslog 配置、service/timer 元数据、包管理历史、shell 痕迹、`/proc/*/exe (deleted)` 等替代证据。
- 对近期本地提权暴露面做只读检测与合理怀疑链整理，关注 sudo 相关问题与 `CopyFail`、`DirtyFrag` 等内核暴露面，但不做利用验证。
- 出正式报告前自动做第二轮自检，避免把当前排查会话、厂商托管启动项、发行版不适用日志路径、漏洞暴露面误写成攻击结论。
- 自动给出“外部补证/跨主机支点”清单，提醒仍需拉取堡垒机、VPN、IdP、云审计、Kubernetes 审计、NAT/DNS 等证据时，不得把主机侧线索强行写成闭环事实。
- 报告前部优先展示“运行参数画像”与高信号结论，减少人工翻全文成本。
- 领导复核报告采用单文件案件报告范式：先给自然段结论，再按“如何发现这个结论”的顺序展开步骤，并内联命令块、关键证据片段、受波及 IP、可疑文件哈希与处置建议。

## 输出结果

默认在当前工作目录下新建案件文件夹并生成案件包：

```text
./
`-- <host-or-ip>-<utc-timestamp>/
    |-- artifacts/
    |-- evidence/
    |-- leadership-report.md
    |-- meta/
    |   `-- report-manifest.json
    |-- report.md
    `-- reports/
        |-- external-evidence-checklist.md
        |-- operator-brief.md
        `-- operator-brief.json
```

固定输出约束：

- 成功导出时，以上文件集合必须齐全；缺少任意核心文件都应视为导出失败，而不是“部分成功”。
- 公开交付产物已经改为**中文单轨**，文件名不再带 `zh-CN` 后缀。
- 当前默认流程只生成本节列出的中文单轨公开产物；旧版双轨/多摘要公开产物均已废弃，不属于当前交付结果。
- `leadership-report.md` 是给领导或复核人的单文件汇总件，不需要再跳转其它文件即可了解案件全貌、关键证据和处置建议。
- `meta/report-manifest.json` 会记录本次应存在的固定产物清单，便于核对交付完整性。
- 即使远程采集失败，也应在当前案件目录内落下 `failure bundle`、`report.md`、`leadership-report.md`、`reports/operator-brief.md` 和 `reports/external-evidence-checklist.md`，不能因为一条登录链路失败就什么都不产出。

建议阅读顺序：

1. `leadership-report.md`
2. `report.md`
3. `reports/operator-brief.md`
4. `reports/external-evidence-checklist.md`

其中：

- `leadership-report.md`：给领导或复核人直接阅读的独立汇总件，采用“结论 -> 发现过程 -> 受波及 IP -> 可疑文件与哈希 -> 处置建议”的案件报告结构，内联必要命令和关键证据片段。
- `report.md`：完整证据报告，保留证据编号、证据链、时间线、横向目标复核、隐藏进程复核和详细上下文。
- `reports/operator-brief.md`：给非安全同学执行落地动作时参考的简报，默认也是中文。
- `reports/external-evidence-checklist.md`：明确告诉使用者当前还缺哪些主机外证据，避免主机侧线索被误写成闭环事实。

## 项目结构与文件职责

以下结构以当前主流程和核心脚本为准。

```text
.
|-- SKILL.md
|-- README.md
|-- package.json
|-- agents/
|   `-- openai.yaml
|-- references/
|   |-- diagnostic-playbook.md
|   |-- command-trust-verification.md
|   |-- dual-use-remote-tool-review.md
|   |-- harness-discipline.md
|   |-- log-loss-fallbacks.md
|   |-- os-compatibility.md
|   |-- second-pass-review.md
|   `-- skill-maintenance.md
|-- scripts/
|   |-- run_readonly_workflow.py
|   |-- collect_live_evidence.py
|   |-- preflight_environment.py
|   |-- enrich_case_evidence.py
|   |-- review_case_evidence.py
|   |-- export_investigation_report.py
|   |-- export_external_evidence_checklist.py
|   |-- nl_control.py
|   |-- generate_operator_brief.py
|   |-- generate_reports_from_bundle.py
|   |-- compare_case_bundles.py
|   |-- generate_host_baseline.py
|   |-- apply_host_baseline.py
|   |-- validate_case_bundle.py
|   |-- command_guard.py
|   |-- refresh_case_bundle.py
|   |-- redact_output.py
|   `-- install-skill.mjs
`-- reports/
    `-- .gitkeep
```

关键文件说明：

- `SKILL.md`：运行时契约，定义边界、流程、门禁与报告标准。
- `SKILL.md` 保持短小，复杂分支、例外路径和分支矩阵下沉到 `references/`，更符合 skill 的检索与执行习惯。
- `agents/openai.yaml`：技能入口元数据与绑定配置。
- `scripts/run_readonly_workflow.py`：主编排器，串起采集、富化、校验、导出。
- `scripts/collect_live_evidence.py`：多路径只读采集（本地/远程、命令降级、超时控制）。
- `scripts/enrich_case_evidence.py`：证据关联、时间线重建、假设矩阵生成。
- `scripts/enrich_case_evidence.py` 现在还会补 `auth_attack_review`、`lateral_movement_review`、`hidden_process_review`，用于保守横向目标判断和隐藏进程复核。
- `scripts/review_case_evidence.py`：二轮复核层，专门处理时间线质量、范围闭环、发行版日志布局、误报风险和外部补证支点。
- `scripts/export_investigation_report.py`：导出当前中文单轨公开报告，固定产出 `report.md` 与 `leadership-report.md`。
- `scripts/nl_control.py`：自然语言请求解析与参数映射。
- `scripts/generate_operator_brief.py`：面向非安全同学的中文简报生成。
- `scripts/generate_reports_from_bundle.py`：仅根据当前案件目录里的现有证据重新生成报告，不重新登录主机、不重新采集。
- `scripts/command_guard.py`：危险命令门禁与审批约束。
- `references/`：排查手册、降级策略、兼容性与维护规范。
- `references/harness-discipline.md`：给弱模型或复杂现场使用的证据关联护栏，强制区分主结论与待证实线索。
- `references/dual-use-remote-tool-review.md`：处理向日葵、ToDesk 等双用途远控工具，避免把合法运维和攻击者借用混为一谈。
- `references/deception-and-contradiction-review.md`：专门处理假信息、误导性日志和跨来源矛盾。
- `references/second-pass-review.md`：明确二轮复核的必查门槛，约束模型在出报告前先做闭环检查。

## 安装

安装到 Agents：

```bash
node scripts/install-skill.mjs install --target agents --force
```

安装到其它目标：

```bash
node scripts/install-skill.mjs install --target codex --force
node scripts/install-skill.mjs install --target cc-switch --force
```

如果本机 `Codex` 已经装过旧版本，推荐直接执行上面的 `--target codex --force`。
它会覆盖 `~/.codex/skills/mining-host-troubleshooter-skill`，并清理旧的历史目录别名，避免“仓库已更新但本机仍在跑旧 skill”。

自定义安装目录：

```bash
node scripts/install-skill.mjs install --dest /path/to/skills --name mining-host-troubleshooter-skill --force
```

查看默认目标路径：

```bash
node scripts/install-skill.mjs print-targets
```

发布到 npm（或私有 registry）后，也可通过：

```bash
npx mining-host-troubleshooter-skill install --target agents
```

更新本机已安装 skill 后，重启 `Codex` 再加载新版本。

## 安全边界

下列操作必须人工确认后才允许执行：

- 杀进程
- 停服务
- 删除或移动文件
- 修改配置或启动项
- 重启或中断业务

补充约束：

- 即使使用者在自然语言里直接要求 `kill`、`stop`、`delete`、`restart`，这个 skill 也默认只会继续做只读取证，并把这些动作记录为后续需单独审批的建议。

## 维护说明

维护者流程、校验与发布规范见：`references/skill-maintenance.md`。
