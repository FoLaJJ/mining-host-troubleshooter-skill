# Mining Host Troubleshooter

[English README](README.en.md)

用于 Linux 主机疑似挖矿入侵的只读排查与溯源技能。

这个仓库是一个 **skill**，不是给用户手工拼脚本参数的命令集合。正常使用方式是让大模型调用 skill，skill 再自动编排脚本执行与报告导出。

## 核心定位

- 最小破坏：默认只读，优先保现场。
- 证据驱动：先采集证据，再输出结论。
- 结论分级：区分观测事实、推断、归因，并给出置信度。
- 审批门禁：任何状态变更操作必须先得到明确确认。

## 适用场景

- Linux 主机出现异常 CPU/GPU 占用，怀疑挖矿或伪装挖矿。
- 可疑服务、启动项、计划任务、容器行为需要追根溯源。
- 业务主机需要低扰动、可追溯的只读排查流程。
- 日志缺失或被清理，需要通过残留证据尽量还原现场。

## 如何使用（面向 skill 调用）

直接在对话中调用 skill，不需要手工运行脚本：

- `$mining-host-troubleshooter 排查 <HOST_IP>，账号 <REMOTE_USER>，密码 <PASSWORD>，重点看 GPU 挖矿`
- `$mining-host-troubleshooter 本机疑似挖矿，先做只读排查并导出中文报告`
- `$mining-host-troubleshooter 对这台机器做跨案件差异比对，并输出结论置信度`

你可以继续用自然语言追加控制条件，例如：

- “先不要执行任何变更操作，只做只读取证。”
- “如果要 kill/stop/delete，先告诉我影响和回滚方案，再等我确认。”
- “报告里保留可溯源 IP，不要隐藏。”

## 技能内部排查流程

1. **Trust Bootstrap**：确认目标身份、校验 SSH 信任链（`known_hosts`/指纹）。
2. **Readonly Sweep**：执行低影响只读采集，带超时、检查点、降级兜底。
3. **Deep Evidence Correlation**：关联进程、网络、持久化、容器、云线索、GPU 进程映射。
4. **Confidence-Gated Conclusion**：按证据完整度输出 `confirmed` 或 `inconclusive`，禁止杜撰。
5. **Approval-Gated Response**：仅输出处置建议，变更操作必须显式审批。

## 输出结果

默认在当前工作目录生成案件包：

```text
reports/
`-- <host-or-ip>-<utc-timestamp>/
    |-- artifacts/
    |-- evidence/
    |-- meta/
    |-- report.md
    |-- report.zh-CN.md
    `-- reports/
        |-- index.md
        |-- index.zh-CN.md
        |-- management-summary.md
        |-- management-summary.zh-CN.md
        |-- soc-summary.md
        |-- soc-summary.zh-CN.md
        |-- operator-brief.md
        |-- operator-brief.zh-CN.md
        `-- operator-brief.json
```

建议阅读顺序：

1. `reports/index.zh-CN.md`
2. `reports/management-summary.zh-CN.md` 或 `reports/soc-summary.zh-CN.md`
3. `report.zh-CN.md`

## 项目结构与文件职责

```text
.
|-- SKILL.md
|-- README.md
|-- README.en.md
|-- package.json
|-- agents/
|   `-- openai.yaml
|-- references/
|   |-- diagnostic-playbook.md
|   |-- command-trust-verification.md
|   |-- log-loss-fallbacks.md
|   |-- os-compatibility.md
|   `-- skill-maintenance.md
|-- scripts/
|   |-- run_readonly_workflow.py
|   |-- collect_live_evidence.py
|   |-- enrich_case_evidence.py
|   |-- export_investigation_report.py
|   |-- nl_control.py
|   |-- generate_operator_brief.py
|   |-- compare_case_bundles.py
|   |-- generate_host_baseline.py
|   |-- apply_host_baseline.py
|   |-- validate_case_bundle.py
|   |-- command_guard.py
|   `-- install-skill.mjs
`-- reports/
    `-- .gitkeep
```

关键文件说明：

- `SKILL.md`：运行时契约，定义边界、流程、门禁与报告标准。
- `agents/openai.yaml`：技能入口元数据与绑定配置。
- `scripts/run_readonly_workflow.py`：主编排器，串起采集、富化、校验、导出。
- `scripts/collect_live_evidence.py`：多路径只读采集（本地/远程、命令降级、超时控制）。
- `scripts/enrich_case_evidence.py`：证据关联、时间线重建、假设矩阵生成。
- `scripts/export_investigation_report.py`：导出中英文主报告与分层摘要。
- `scripts/nl_control.py`：自然语言请求解析与参数映射。
- `scripts/generate_operator_brief.py`：面向非安全同学的简报生成。
- `scripts/command_guard.py`：危险命令门禁与审批约束。
- `references/`：排查手册、降级策略、兼容性与维护规范。

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

自定义安装目录：

```bash
node scripts/install-skill.mjs install --dest /path/to/skills --name mining-host-troubleshooter --force
```

查看默认目标路径：

```bash
node scripts/install-skill.mjs print-targets
```

发布到 npm（或私有 registry）后，也可通过：

```bash
npx mining-host-troubleshooter-skill install --target agents
```

## 安全边界

下列操作必须人工确认后才允许执行：

- 杀进程
- 停服务
- 删除或移动文件
- 修改配置或启动项
- 重启或中断业务

## 维护说明

维护者流程、校验与发布规范见：`references/skill-maintenance.md`。
