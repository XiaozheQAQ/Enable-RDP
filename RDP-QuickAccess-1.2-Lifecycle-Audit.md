# RDP-QuickAccess 1.2 — Lifecycle Regression Audit

日期：2026-11-21  
分支：`feature/public-network-support`  
审计基线：`3a623ec7caabf987cb3d7f338765af1d1fa0fac1`  
修复提交：`6830ce150df25d1879ddb0b88d9c7a6f72e41c32`

## 摘要

本轮对 RDP-QuickAccess 1.2 的生命周期进行专项审计，重点检查：

- `Restore-RdpRegistryValue`
- `Restore-RdpRegistryState`
- `DisableRdp` / `DisableAndDelete`
- 状态快照与注册表写入值的一致性
- 五个生命周期场景
- 外部修改保护
- SchemaVersion 兼容性
- Public 网络支持是否退化

审计发现并修复了一个真实缺陷：DisableRdp 主动写入 `fDenyTSConnections=1` 后，RestoreOriginal 仍按固定“工具写入值 0”判断，误把该写入识别为管理员外部修改，导致场景 A 无法恢复原始值。

修复后，生命周期五场景和相关边界测试全部通过。

## 问题根因

1.2 的 Restore 逻辑原本使用：

- `fDenyTSConnections` 的工具写入值固定为 `0`
- `UserAuthentication` 的工具写入值固定为 `1`

Enable 写入 `fDenyTSConnections=0` 时两者一致，因此正常。

但 DisableRdp 会主动写入：

```text
fDenyTSConnections = 1
```

旧状态快照只保存运行前原始值，没有保存“本工具最近一次写入值”。

因此 RestoreOriginal 读到：

- 当前值：`1`
- 原始快照：`0`
- 假定工具写入值：`0`

判断为：

> 当前值既不等于快照，也不等于工具写入值，可能被管理员修改，跳过恢复。

结果：场景 A 中 DisableRdp 后执行 RestoreOriginal，`fDenyTSConnections` 仍为 `1`，没有恢复为 `0`。

## 修复设计

### 1. 新增 LastApplied 状态

状态快照新增：

```text
Rdp.LastApplied.fDenyTSConnections
Rdp.LastApplied.UserAuthentication
```

它记录本工具最近一次主动写入的注册表值，不替代运行前原始快照。

写入时机：

| 操作 | 记录内容 |
|---|---|
| Enable 成功设置 RDP/NLA | `0 / 1` |
| DisableRdp 成功关闭 RDP | `fDenyTSConnections=1` |
| DisableAndDelete | 通过 DisableRdp 记录 `1` |
| RestoreOriginal 恢复成功 | 更新为该值的原始快照值 |
| 部分恢复、快照保留 | 保存更新后的 LastApplied |

### 2. Restore 使用最新工具写入值

`Restore-RdpRegistryState` 不再使用固定值，而是读取 `Rdp.LastApplied`。

恢复判断：

1. 当前值等于原始快照：`AlreadyOriginal`，不需要写入。
2. 当前值等于工具最新写入值：恢复原始快照。
3. 当前值既不等于快照，也不等于工具最新写入值：判定为外部修改，跳过覆盖。

这样既修复了 DisableRdp 后的恢复问题，也保留了真正的外部修改保护。

### 3. 部分恢复后的保护

如果 RestoreOriginal 因为账户存在活动会话而部分完成：

- 已成功恢复的注册表值会更新 LastApplied 为原始值。
- 状态快照保留，并保存更新后的 LastApplied。
- 后续管理员再次修改该值时，不会被旧的 LastApplied 误判为工具写入。

## 五场景回归

| 场景 | 验证结果 |
|---|---|
| A：原始 RDP 已开启 | 通过。Enable 后 0，DisableRdp 后 1，RestoreOriginal 后恢复 0；NLA=1；TermService 恢复；账户和规则清理；完整成功后快照删除 |
| B：原始 RDP 已关闭 | 通过。Enable 后 0，DisableRdp 后 1，RestoreOriginal 后保持 1；快照删除 |
| C：DisableAndDelete 后恢复 | 通过。RDP 恢复原始配置；账户和防火墙规则删除；仅完整成功后清理快照 |
| D：Disable 后重新 Enable | 通过。第二次 Enable 复用原始快照，不覆盖首次 Enable 前的配置；最终恢复初始状态 |
| E：账户活动会话导致删除失败 | 通过。账户保留，不强制注销；RDP 恢复原始配置；快照保留；输出 PARTIAL；后续仍可安全恢复 |

## 额外边界验证

- 外部把 `fDenyTSConnections` 改为 `1`：RestoreOriginal 不覆盖，快照保留。
- 外部修改 TermService 启动类型：不覆盖。
- 原始 NLA=0：Enable 设 1，RestoreOriginal 恢复 0。
- 旧 SchemaVersion 1：可读、可迁移、可完成 DisableRdp 和 RestoreOriginal。
- 部分恢复后 LastApplied 更新为原始值，后续外部修改不会被误判。
- 快照只在完整恢复成功时清理。

## SchemaVersion 兼容

| 项目 | 行为 |
|---|---|
| 新快照 | `SchemaVersion = 2` |
| 旧快照 | `SchemaVersion = 1` 仍可读取 |
| 旧快照缺少 LastApplied | 内存中补默认值：`fDenyTSConnections=0`、`UserAuthentication=1` |
| 旧快照保存 | 下次 Save 时升级为 SchemaVersion 2 |
| 原始快照值 | 不迁移、不覆盖 |
| 密码 | 不写入状态文件 |

## 测试结果

| 测试 | 结果 |
|---|---|
| 生命周期五场景 + 边界回归 | 68 / 68 通过 |
| Public / Private / Domain 网络回归 | 19 / 19 通过 |
| PowerShell 5.1 AST | 0 错误，69 个函数 |
| 真实系统写入 | 未执行 |
| 真实账户创建/删除 | 未执行 |
| 真实防火墙规则创建/删除 | 未执行 |
| 真实注册表修改 | 未执行 |

测试使用 mock 注册表、临时状态目录和隔离的 mock 账户/防火墙/服务。

## 系统状态确认

测试后检查：

- `rdp_access` 账户：不存在
- `RDP-QuickAccess-TCP` 规则：不存在
- RDP 注册表：`fDenyTSConnections=0`，`UserAuthentication=1`
- TermService：Running / Manual
- 当前网络：WLAN / Public
- 既有 `%ProgramData%\RDP-QuickAccess` 状态目录：未被修改，时间戳保持 `2026-11-21 11:22:11`

## Public 网络支持

本轮未修改 Public/Private/Domain 网络预检、防火墙 Profile 或 LocalSubnet 规则逻辑。

Public 回归覆盖：

- Public / Private / Domain 预检通过
- 未知类别明确拒绝
- 活动 Public 防火墙启用/关闭判断
- 活动 Private 防火墙关闭拒绝
- 非活动 Profile 只警告
- 三 Profile 防火墙规则验证
- 缺 Public、RemoteAddress=Any、端口范围、UDP 拒绝
- Public + LocalSubnet 不误报风险
- 新建/更新规则包含 Domain/Private/Public

## 修改文件

| 文件 | 变更 |
|---|---|
| `RDP-QuickAccess.ps1` | 92 行新增，4 行删除 |
| BAT 文件 | 未修改 |

PS1 SHA-256：

```text
03F9C8B623448C8546ABEE05EC99345458931C67956E7A388A054ACF5739959A
```

## Git 信息

- Repository: https://github.com/XiaozheQAQ/Enable-RDP
- Branch: `feature/public-network-support`
- 修复 Commit: `6830ce150df25d1879ddb0b88d9c7a6f72e41c32`
- 前一 Commit: `3a623ec7caabf987cb3d7f338765af1d1fa0fac1`
- main: `5bf598fe29f93c77d6988600bc938a99f9d8fc1f`
- 未修改 main
- 已推送 feature 分支到远端

Pull Request 创建入口：

https://github.com/XiaozheQAQ/Enable-RDP/pull/new/feature/public-network-support

## 尚未执行的验证

- 未执行真实 Enable / DisableRdp / RestoreOriginal，避免修改真实系统。
- 活动会话场景使用 mock 会话验证，未强制注销真实用户。
- TermService 恢复函数使用 mock 服务验证，未真实修改服务启动类型。
- 既有状态目录内容未读取，保持原样。
- 对修复前由旧代码写入但未记录 LastApplied 的异常快照，直接 Restore 会保守跳过不一致值；再次执行 DisableRdp 可记录最新工具值后正常恢复。
