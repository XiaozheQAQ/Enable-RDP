# RDP-QuickAccess

Windows 10/11 局域网 RDP 一键配置、状态检查和生命周期管理工具。

当前代码基线：**1.2**（含 Public 网络支持、多入口管理和生命周期状态一致性修复）。

- 发布下载：<https://github.com/XiaozheQAQ/Enable-RDP/releases>
- 生命周期审计报告：[RDP-QuickAccess-1.2-Lifecycle-Audit.md](RDP-QuickAccess-1.2-Lifecycle-Audit.md)

> 本项目面向**可信局域网**。它不是公网 RDP 暴露工具，也不会修改路由器、UPnP 或端口映射。

## 功能

- 开启/维护 RDP，强制启用 NLA。
- 创建或轮换独立本地账户 `rdp_access`，使用 24 位 CSPRNG 随机密码。
- 创建仅允许 `LocalSubnet` 的 TCP 3389 入站防火墙规则。
- 支持 `Domain` / `Private` / `Public` 网络配置文件，不自动修改网络类别。
- 关闭新的 RDP 连接，但保留账户和状态快照。
- 单独删除受管账户；有活动会话时拒绝删除，不强制注销。
- 只读状态检查。
- 按快照完整恢复运行前配置。
- 多入口 BAT，所有业务逻辑仍集中在 `RDP-QuickAccess.ps1`。
- 同一时间只允许一个操作实例，避免并发修改。

## 系统要求

- Windows 10/11 专业版、企业版、教育版或专业工作站版。
- Windows PowerShell 5.1（系统自带）。
- 管理员权限（`RDP-QuickAccess.bat -Help` 除外）。
- RDP 端口必须已经是 3389；本工具不修改端口。
- 不支持 Windows 家庭版（Home）和 Windows Server。

## 快速开始

1. 下载并解压 Release 中的 ZIP，或获取完整源码目录。
2. 保持所有 BAT 与 `RDP-QuickAccess.ps1` 在同一目录。
3. 双击 `RDP-Enable.bat`，在 UAC 提示中允许管理员权限。
4. 记录窗口显示的连接地址、账户和一次性密码。

所有 BAT 都会自动请求管理员权限，使用自身目录定位 PS1，支持中文和空格路径。

## 入口与参数

| BAT | PowerShell 参数 | 用途 |
|---|---|---|
| `RDP-Enable.bat` | `-Enable` | 开启/维护 RDP，创建或轮换账户，显示凭证 |
| `RDP-Disable.bat` | `-DisableRdp` | 关闭新的 RDP 连接，删除受管规则，保留账户和快照 |
| `RDP-Delete-Account.bat` | `-DeleteAccount` | 只删除受管账户 |
| `RDP-Disable-And-Delete.bat` | `-DisableAndDelete` | 关闭 RDP、删除规则，并在无活动会话时删除账户 |
| `RDP-Status.bat` | `-Status` | 只读检查 |
| `RDP-Restore-Original.bat` | `-RestoreOriginal` | 完整恢复运行前快照 |
| `RDP-QuickAccess.bat` | 默认 / `-Status` / `-Disable` / `-Help` | 向后兼容入口 |

说明：

- 直接运行 `RDP-QuickAccess.bat` 等同于开启。
- 旧版 `RDP-QuickAccess.bat -Disable` 是 `-RestoreOriginal` 的兼容别名，仍然执行完整恢复。
- 新的关闭命令是 `RDP-Disable.bat`，它只关闭新的 RDP 接入，不删除账户。
- 多个操作参数同时使用会被拒绝。

## 操作语义

### 开启 / Enable

- 检查系统版本、RDP Host、TermService、网络配置和防火墙。
- 保存运行前配置快照。
- 启用 RDP，强制 NLA。
- 创建或维护 `rdp_access`，轮换密码。
- 创建或更新 `RDP-QuickAccess-TCP` 防火墙规则。
- 验证 RDP 状态并显示连接信息。

### 关闭 / DisableRdp

- 设置 `fDenyTSConnections=1` 并验证。
- 删除本工具管理的防火墙规则。
- **保留** `rdp_access` 账户。
- **保留**状态快照。
- 不修改 NLA，不停止 TermService，不强制注销已有会话。

### 删除账户 / DeleteAccount

- 只删除 `rdp_access`。
- 校验说明字段 `Managed by RDP-QuickAccess`。
- 如果快照记录了 `AccountSid`，必须与当前账户 SID 一致。
- 检查本地/远程/未注销会话；有会话时拒绝删除。
- 不强制踢出会话，不删除用户配置文件目录。
- 不改变 RDP 状态、防火墙规则或状态快照。

### 关闭并删除 / DisableAndDelete

- 先关闭新的 RDP 接入并删除受管规则。
- 再检查账户会话并尝试删除账户。
- 有活动会话时保留账户并输出 `PARTIAL`，退出码非 0。
- 无论成功还是 PARTIAL，都保留状态快照。

### 状态 / Status

只读显示：

- Windows 版本、RDP、NLA、Listener、TermService。
- 当前活动网络配置文件、三种防火墙 Profile。
- 受管规则、TCP 3389、LocalSubnet、三 Profile 属性。
- 账户存在、启用、Remote Desktop Users、Administrators。
- 状态快照和状态目录 ACL。

### 恢复 / RestoreOriginal

- 按快照恢复 RDP 注册表和 TermService 启动类型。
- 删除受管账户和防火墙规则。
- 有活动会话时保留账户，快照保留。
- 不猜测缺失或损坏的原始配置。
- 只有完整恢复成功后才清理状态快照。

## 网络与防火墙

- 防火墙规则：TCP 3389、入站、允许、`RemoteAddress=LocalSubnet`。
- Profile：`Domain`、`Private`、`Public`。
- 不把 `RemoteAddress` 改成 `Any`。
- 不添加 UDP、不关闭防火墙、不修改默认策略。
- 不自动修改网络配置文件类型。
- Public 支持要求当前活动 Public 防火墙已启用；工具不会自动开启防火墙。

`LocalSubnet` 只限制来源网段，不等于“只有我的设备”。同一局域网或 Public Wi-Fi 上的其他设备仍可能访问 TCP 3389。不同路由网段、VPN、CGNAT、路由器 NAT、客户端隔离或 ACL 不保证可达。

## 账户与会话安全

- 账户固定为 `rdp_access`，不是 Windows 主账户。
- 密码为 24 位 CSPRNG 随机值，只在成功后显示一次，不保存、不写日志、不自动复制。
- 账户不属于 Administrators；删除前如果发现，会先移除管理员成员资格。
- 删除账户前检查 `quser`、登录会话和进程所属用户。
- 存在活动/断开未注销会话时拒绝删除，不强制注销、不结束用户进程。
- 不删除 `C:\Users\rdp_access` 或任何个人文件。
- 账户生命周期由独立 BAT 显式控制；关闭窗口不会删除账户。

## 状态快照

默认路径：

```text
%ProgramData%\RDP-QuickAccess\state.json
```

- 当前 `SchemaVersion = 2`。
- 旧 `SchemaVersion = 1` 仍可读取；缺少 `LastApplied` 时按旧工具写入值补默认值，并在下次保存时升级。
- `Rdp.LastApplied` 记录本工具最近一次主动写入的注册表值，用于区分工具写入和管理员外部修改。
- 外部修改保护仍然有效：当前值既不是原始快照、也不是工具最新写入值时，不覆盖。
- 不把密码写入状态文件。

## 退出码

- `0`：操作成功。
- `1`：操作失败、被拒绝，或组合操作只完成 PARTIAL。
- `2`：主 BAT 收到不支持或过多的参数。

BAT 会把 PowerShell 的退出码返回给调用方；提权失败也会返回非 0。

## 常见问题

### 提示需要管理员权限

在 UAC 提示中选择“是”。如果取消，BAT 会报告提权失败并返回非 0。

### Public 网络无法开启

确认当前活动 Public 防火墙已启用。工具不会自动开启防火墙，也不会把 Public 改成 Private。

### 提示端口不是 3389

本工具不修改 RDP 端口。请先把端口恢复为 3389，或自行处理现有配置。

### 提示账户说明字段不匹配

说明存在同名但不是本工具管理的账户。工具会拒绝操作，不会删除或修改其他账户。

### 删除账户被拒绝

账户可能仍有本地/远程/断开未注销会话，或状态快照 SID 不匹配。先正常注销会话；工具不会强制踢出。

### 状态快照损坏或丢失

工具不会猜测原始配置。恢复命令会报告无法安全恢复的项目；必要时手动检查 RDP 注册表和服务配置。

## 已知限制

- 仅支持局域网 RDP，不提供公网暴露、NAT 穿透或端口映射。
- 不提供 MFA/双因素认证。
- 不修改 RDP 端口、安全层或全局密码策略。
- 不保证跨路由网段、VPN、CGNAT、NAT、客户端隔离或 ACL 可达。
- 域策略或第三方安全软件仍可能阻止连接。
- Windows 家庭版和 Windows Server 不受支持。

## 文件结构

```text
RDP-QuickAccess.ps1                 核心 PowerShell 实现
RDP-QuickAccess.bat                 向后兼容入口
RDP-Enable.bat                      开启
RDP-Disable.bat                     关闭新的 RDP 接入
RDP-Delete-Account.bat              只删除账户
RDP-Disable-And-Delete.bat          关闭并删除
RDP-Status.bat                      只读状态
RDP-Restore-Original.bat            完整恢复
RDP-QuickAccess-1.2-Lifecycle-Audit.md  生命周期审计报告
```

## 安全说明

本工具不会关闭防火墙、不会开放任意公网来源、不会修改网络配置文件类型，也不会修改其他账户或其他防火墙规则。

请在可信网络中使用，并自行评估同子网设备、共享 Wi-Fi、路由器和 ACL 带来的暴露风险。