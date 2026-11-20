# AGENTS.md

本文件定义 AI Agent 参与本项目开发、测试与部署时的长期协作规范、技术栈边界与交付约束。唯一功能规格、数据面设计与验收标准见根目录 [VPS.md](VPS.md)。

## 1. 工作约定

- **最小改动。** 先定位问题，再修改直接相关的代码。优先复用现有逻辑，保留已有配置和对外行为；修复单个问题时避免顺带重构、全仓格式化或更换依赖。
- **留出扩展接口。** 出口协议适配、规则匹配、线路调度、配置迁移各有清晰入口；实现第二种协议或新增规则类型时复用同一边界，不为假设中的功能提前搭框架。
- **测试与改动相称。** 代码改动必须跑构建和相关测试，优先复用现有用例。纯文档改动只检查内容与链接。涉及代理转发、凭据、迁移格式或正式线路的重大变更，补齐相应集成、故障或回滚验证。
- **直接给出判断。** 沟通先给结论，再给必要依据。信息不足时直接指出当前判断、缺少的数据或下一步检查；避免使用“不能证明……”和“不能说明……”等含糊表达。
- **保护真实配置。** 真实地址、端口、密码、私钥、令牌、节点、订阅链接及具体机房拓扑特征不得进入源码、文档、示例、测试样本、截图、日志或对话输出；报错时仅使用出口名、错误类型和脱敏信息。
- **零基础友好交付。** 用户无开发背景。按上述验证规则交付，常用操作收敛为简单命令或一键脚本。涉及界面变更时提供简短中文操作步骤和预期结果。

## 2. 高危操作红线（必须先获确认）

以下操作**严禁自主执行**，必须先向用户展示变更内容、影响范围与回滚方案，获明确确认后再执行：

- 向真实 VPS 写入配置、安装/替换二进制或修改 `systemd` 服务。
- 重载、重启或停止现网代理服务，或执行正式入口切换。
- 修改 VPS 防火墙、SSH 配置、系统网络或路由规则。
- 执行 `git push` 或向外部远程仓库发布代码。

## 3. 锁定技术栈与核心架构约束

- **统一语言与运行环境：** 全栈采用 **C# / .NET 10 LTS**，Windows 开发机仅需安装 `.NET 10 SDK`。
- **Windows 独立桌面应用（WPF）：**
  - 使用 **WPF（`net10.0-windows`）** 开发中文独立桌面程序（不使用 Web UI，不使用 WinUI 3）。
  - 按需打开、关闭即释放 SSH 连接；**不监听任何本地 HTTP/TCP 端口**，消除浏览器 CSRF 与本地端口暴露面。
  - 进程内直接调用 Windows DPAPI（`ProtectedData`）加密 `%LOCALAPPDATA%\VPSPanel\` 下的敏感配置。
- **VPS 侧常驻服务与 Xray 单内核三段式回环链：**
  - 单个 Xray 实例承担入口（VLESS REALITY + `sniffing`）与全部上游/直连出口。
  - 自研调度与限速服务由 C# 编译为 **Linux 自包含单文件二进制**（`SelfContained=true`、`PublishSingleFile=true`，VPS 无需安装 .NET 运行时），由 `systemd` 托管常驻；电脑离线后 VPS 持续工作。
  - 调度服务通过 `127.0.0.1` 回环 SOCKS5（TCP + UDP Associate）夹在 Xray 入口与各独立 `inboundTag` 出口之间。禁止编造不存在的 Xray 插件机制。
- **内核基线与安全变更。** 在隔离环境使用已知的锁定版本验证。配置文件先经 `xray run -test -c` 校验，按根目录规格区分动态出口切换和需要重启的入口变更；后者由 VPS 看门狗负责超时回滚。
- **动态变更与排空。** 新增、切换和移除出口都必须同步原子落盘并静态校验；运行状态与持久化配置一致才报告成功。旧出口停止接收新会话，已有会话自然结束或空闲超时后回收，设最大排空期限。排空不阻塞后续切换，重启恢复最新已提交状态。具体期限与异常处理见 [VPS.md](VPS.md)。
- **桌面视觉约束。** 对齐 Windows 11「设置」。优先使用 .NET 10 原生 WPF Fluent 控件和 Segoe Fluent Icons；需要补足控件时可选成熟 WPF-UI 库。业务卡片可轻量组合，图表优先使用成熟轻量组件。所有自定义表面、文字、状态和图表颜色使用语义画刷并以 DynamicResource 绑定，标准控件继承主题。设置页提供跟随系统、浅色、深色，偏好保存在本地配置目录。
- **界面基线。** 首页与设置的离线实机截图位于 `docs/screenshots/`，文案和字段以 VPS.md 为准。
- **DNS 与备份。** 托管模式下，代理 DoH 经健康上游，全失效时拒绝解析。直连与节点引导使用本机直发的纯 IP DoH，Relay 使用该栏进行直连探活与预检。面板不修改宿主机系统 DNS。已接管主机的常规导出以当前托管配置为底稿，保留有效的非托管入口、前置路由与顺序；历史原件按冷备份保留。
- **共享核心库与匹配单一来源。** 规则匹配、GeoIP/GeoSite 解析、配置模型与加密备份逻辑放在共享类库 `VPSPanel.Core`。固定规则核对实际出口；自动分摊按同一状态快照比较候选与预计出口。
- **SSH 接入与离线分发：**
  - SSH 别名使用系统 `ssh.exe` / `sftp.exe`，兼容本机别名、跳板机与 OpenSSH Agent；该模式由 OpenSSH 管理私钥。主机直连由 SSH.NET 在进程内使用用户提供的密码或选定的本地私钥，凭据与指纹处理遵循 [VPS.md](VPS.md)。
  - VPS 所需的 Xray 二进制、自包含调度服务二进制与 `geoip.dat` / `geosite.dat` 必须支持本机准备并通过 SFTP 离线推送安装。

## 4. Git 管理与防泄漏基线

- 使用本地 Git 仓库与 `main` 分支；**先完成并验证 Git 防泄漏钩子，再连接任何真实 VPS**。
- `.gitignore` 覆盖 `.env`、SSH 配置及常见私钥、私有配置、订阅缓存、运行库/日志、临时部署文件、迁移包以及 `.NET` 构建产物（`bin/`、`obj/`、`publish/`）；仓库仅保留虚构占位的示例配置。
- 通过 `git config core.hooksPath .githooks` 启用入库钩子，钩子入口统一调用仓库内的 C# 校验工具（`VPSPanel.Guard`），兼顾 Windows Git Bash 与 PowerShell。
- `pre-commit` 扫描暂存区、`pre-push` 扫描本次待推送提交历史；校验工具在内存中解密或比对 DPAPI 保护的本机登记 VPS 地址与订阅链接指纹，发现敏感内容时阻止操作且仅输出文件、位置与风险类型。

## 5. 建议目录结构与常用命令

```text
├── src/
│   ├── VPSPanel.Core/      # 共享类库：规则引擎、Geo 解析、配置模型、加密备份
│   ├── VPSPanel.Desktop/   # Windows WPF 独立中文桌面端
│   ├── VPSPanel.Relay/     # VPS 常驻调度与双向限速服务（Linux 自包含单文件）
│   └── VPSPanel.Guard/     # Git 防泄漏扫描与 DPAPI 敏感指纹校验工具
├── tests/
│   └── VPSPanel.Tests/     # 单元测试与集成测试
├── .githooks/              # 入库 Git 钩子（pre-commit / pre-push）
├── scripts/                # 一键构建、测试、桌面端打包与 Linux 交叉编译脚本
└── VPS.md                  # 唯一功能规格与验收清单
```

- 在仓库根目录执行：
  - 构建全部项目：`dotnet build`
  - 运行测试：`dotnet test`
  - 一键启用仓库钩子并构建、测试：双击 [构建与测试.cmd](构建与测试.cmd)
  - 打包桌面端：[scripts/publish-desktop.ps1](scripts/publish-desktop.ps1)，输出 `publish/desktop/VPSPanel.Desktop.exe`
  - 发布 Linux 单文件骨架：[scripts/publish-relay.ps1](scripts/publish-relay.ps1)，默认 linux-x64，可指定 linux-arm64
  - 单独验证 Git 钩子：`dotnet test --filter FullyQualifiedName~GitHookTests`。测试在临时本地仓库直接调用 pre-push 钩子检查待推送历史。
  - 本机登记需要保护的地址或链接：`dotnet run --project src/VPSPanel.Guard -- register`，按提示隐藏输入。登记文件使用当前 Windows 用户的 DPAPI 保护。
