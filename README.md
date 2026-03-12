# Mining Host Troubleshooter

[English README](README.en.md)

用于 Linux 主机疑似挖矿入侵的只读排查与溯源技能。

这套技能的定位很明确：

- 先保现场，再做判断
- 默认只读，不自动处置
- 证据优先，结论分级
- 支持业务主机低扰动排查

## 这个技能能做什么

- 本机或远程主机排查（SSH 私钥、SSH agent、账号密码、跳板机）。
- CPU / GPU / 混合挖矿场景检查。
- 异常进程、伪装服务、持久化项、容器与云侧线索联动检查。
- 兼容常见 Linux 发行版差异，命令缺失时自动降级到替代路径。
- 日志缺失时使用替代证据继续还原现场（`wtmp`、`btmp`、`lastlog`、`/proc` 等）。
- 输出结构化案件包（证据、产物、时间线、结论、摘要报告）。
- 输出“假设-证据矩阵”，明确支撑证据、反证与置信度。
- 生成面向非安全同学的简报（operator brief）。

## 这个技能不做什么

- 不自动 kill 进程、停服务、删文件、改配置。
- 不在证据不足时给强结论。
- 不把“高 CPU / 高 GPU”直接等同于入侵。

## 安装

### 从当前仓库安装

```bash
node scripts/install-skill.mjs install --target agents --force
```

可选目标：

```bash
node scripts/install-skill.mjs install --target codex --force
node scripts/install-skill.mjs install --target cc-switch --force
```

自定义目录：

```bash
node scripts/install-skill.mjs install --dest /path/to/skills --name mining-host-troubleshooter --force
```

查看默认安装路径：

```bash
node scripts/install-skill.mjs print-targets
```

### 通过 npx 安装

发布到 npm（或私有 registry）后可用：

```bash
npx mining-host-troubleshooter-skill install --target agents
```

## 快速开始

下面示例里的 `<...>` 都是占位符。

### 1) 远程主机（SSH 私钥）

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

### 2) 远程主机（账号密码）

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

### 3) 远程快速直连（IP + 账号 + 密码）

```bash
export SSH_PASSWORD='<PASSWORD>'
python scripts/run_readonly_workflow.py \
  --remote-user <REMOTE_USER> \
  --remote-ip <HOST_IP> \
  --port <SSH_PORT> \
  --password-env SSH_PASSWORD \
  --trust-on-first-use \
  --analyst <ANALYST> \
  --host-ip <HOST_IP> \
  --os-hint "<OS_HINT>" \
  --mining-mode auto \
  --profile enterprise-self-audit \
  --strict-report
```

说明：`--trust-on-first-use` 仅适合首次、内部、紧急排查。高风险目标仍建议指纹强校验。

### 4) 自然语言入口

```bash
python scripts/nl_control.py \
  --request "排查 <HOST_IP>，用户名 <REMOTE_USER>，密码 <PASSWORD>，端口 <SSH_PORT>，重点看 gpu 挖矿" \
  --analyst <ANALYST>
```

### 5) 本机排查

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

## 报告与目录结构

默认输出到当前工作目录下的 `reports/`：

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

推荐阅读顺序：

1. `reports/index.zh-CN.md`
2. `reports/management-summary.zh-CN.md` 或 `reports/soc-summary.zh-CN.md`
3. `report.zh-CN.md`

## 现场排查顺序（默认流程）

1. 确认目标主机身份与权限边界。
2. 校验 SSH 信任链（`known_hosts` 或指纹）。
3. 执行低影响只读采集。
4. 关联进程、网络、持久化、启动面和容器/云线索。
5. 重建时间线并标记不确定性。
6. 生成分层报告与证据索引。
7. 仅在审批后再讨论处置动作。

## 日志被删了还能查什么

即便 `auth.log` / `secure` / `syslog` 被清理，流程仍会继续检查：

- 登录数据库：`wtmp`、`btmp`、`lastlog`
- 服务与启动面：`systemd`、`timer`、`cron`、`authorized_keys`、`/etc/ld.so.preload`
- shell 与工具痕迹：`.wget-hsts`、`.lesshst`、`.viminfo`、`.python_history`
- 运行时残留：`/proc/*/exe (deleted)`、当前监听端口与连接

## 基线与跨案件比对

- 同机基线只用于同一台主机历史比对，不能当跨机器“清白证明”。
- 样本过少的基线只能作为弱参考，不能单独下结论。

生成同机基线：

```bash
python scripts/generate_host_baseline.py \
  --reports-root reports \
  --host-ip <HOST_IP>
```

跨案件比对：

```bash
python scripts/compare_case_bundles.py \
  --base-case reports/<older-case> \
  --target-case reports/<newer-case>
```

## 安全边界

下列动作必须人工确认后才允许执行：

- 杀进程
- 停服务
- 删除或移动文件
- 修改配置或启动项
- 重启或中断业务

## 文档导航

- `SKILL.md`：运行时核心契约。
- `references/`：详细排查手册与降级说明。
- `scripts/`：执行脚本与工具。
- `references/skill-maintenance.md`：维护者发布与校验流程。
