# VPSPanel · VPS 代理管理面板

VPSPanel 是一个中文 Windows 桌面程序，用来管理自己 Linux VPS 上的代理出口、网站分流和带宽。桌面端通过 SSH 读取配置、编辑草稿和发布变更。Xray 负责协议传输，VPS 上常驻的 Relay 负责按规则选择出口和限速。关闭面板或电脑后，已发布的规则继续生效。

## 安装与首次使用

### 1. 在 Windows 上打开面板

1. 在 64 位 Windows 电脑上安装 **.NET 10 桌面运行时**。在微软页面找到 **.NET Desktop Runtime 10.0**，选择 **Windows → x64**。[微软官方下载](https://dotnet.microsoft.com/zh-cn/download/dotnet/10.0)
2. 下载 Windows 桌面包，把 ZIP **全部解压**到一个固定文件夹。保留其中的 DLL 和其他配套文件。[下载 Windows x64 桌面包](https://github.com/Teresia-awa/VPSPanel/releases/latest/download/VPSPanel-Desktop-win-x64.zip)
3. 打开解压后的文件夹，双击 **`VPSPanel.Desktop.exe`**。想先熟悉界面，可以双击同目录的 **`本地演示.cmd`**，用虚构数据体验各页面。

### 2. 按需准备 Linux VPS 的离线安装材料

查看界面或通过 SSH 只读查看已有 VPS，下载桌面包即可。要**为 Linux x64 VPS 导出自包含备份**，再下载离线材料包。它包含 Linux Relay、Xray、两份 Geo 规则数据和校验清单。[下载 Linux x64 离线材料包](https://github.com/Teresia-awa/VPSPanel/releases/latest/download/VPSPanel-Recovery-linux-x64.zip)

在 **Windows 电脑上**解压材料包，把里面的整个 `recovery-assets` 文件夹放到 `VPSPanel.Desktop.exe` 旁边。重新打开面板后，「备份与迁移」会自动识别。也可以在该页手动选择**直接包含 `assets.json` 的文件夹**。

```text
VPSPanel/
├─ VPSPanel.Desktop.exe
├─ 本地演示.cmd
├─ …其他桌面文件
└─ recovery-assets/
   ├─ assets.json
   ├─ relay
   ├─ xray
   ├─ geoip.dat
   └─ geosite.dat
```

要把自己的配置迁到新 VPS，先用面板导出加密的 **`.vpspack`**。已有该文件和口令时，在「备份与迁移」中选择它并填写新机的 SSH 登录信息即可。程序会从恢复包取出安装件和配置，通过 SFTP 传到新机。完整恢复条件见下文「备份与更换 VPS」。

### 3. 首次连接自己的 VPS

在首页点击「SSH 连接」。已有 OpenSSH 别名就选「SSH 别名」，也可选「主机直连」，填写主机 IP 或域名、SSH 端口、用户名和实际的 systemd 服务名，用密码或本地私钥登录。首次直连时，从 VPS 控制台等可信渠道核对主机指纹，然后确认信任。点击「只读读取配置」，看到 Xray 版本和入口、出口、路由快照即已连通。已接管的主机还可以读取 Relay 统计和预览发布。

<details>
<summary>校验下载文件或从源码构建（可选）</summary>

若要核对下载完整性，在 ZIP 所在目录打开 PowerShell，运行下列命令，将结果与同一版的校验清单比较。[最新正式版与 SHA-256 清单](https://github.com/Teresia-awa/VPSPanel/releases/latest)

```powershell
Get-FileHash .\VPSPanel-Desktop-win-x64.zip -Algorithm SHA256
Get-FileHash .\VPSPanel-Recovery-linux-x64.zip -Algorithm SHA256
```

开发者可在 Windows 安装 Git 和 .NET 10 SDK，克隆仓库后双击根目录的「构建与测试.cmd」。首次还原依赖需要联网。双击「本地演示.cmd」可启动演示。要生成正式程序，在仓库根目录运行以下命令，输出在 `publish/desktop/`。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\publish-desktop.ps1
```

</details>

## 面板里的功能

| 页面 | 可以做什么 |
| --- | --- |
| 首页 | 查看最近的只读快照、各出口健康与延迟、活跃连接、上下行速率和近期新连接分配比例。使用「刷新」核对当前状态。 |
| 出口管理 | 添加 HY2 或 VLESS REALITY 出口，支持分享链接或手工输入。可维护连接域名、TLS 名称和多个备用域名，启停、删除出口，设置每个方向的带宽上限。规则按稳定 ID 引用出口，修改显示名或切换备用域名后仍沿用原绑定。 |
| 规则与测试 | 网站规则按顺序匹配，可匹配完整域名、域名后缀、IP 网段，也可以引用规则集。规则集可手工编辑、批量粘贴、从文件导入或引用 GeoSite / GeoIP 分类。「测试目标」显示命中的规则、规则集及预计出口，自动分摊时还显示快照时间和健康候选。 |
| 备份与迁移 | 生成加密、自包含的恢复包，离线校验完整性，并通过 SSH/SFTP 恢复到另一台兼容 VPS。页面保留最近操作和验证结果。 |
| 设置 | 切换跟随系统、浅色或深色主题，为当前中转主机选择固定出口不可用时的处理策略。 |

### 分流与限速怎样生效

规则集保存一组匹配条件，网站规则决定匹配后的动作。举例说，可以用一条规则让整个 `.cn` 后缀直连，再把仅匹配 `example.cn` 的指定出口规则放在它前面。未命中的目标使用表格下方选择的默认动作，可选中转 VPS 直连、某个已配置出口或自动分摊。

选择「自动分摊」时，Relay 为每条新 TCP 连接或新 UDP 会话从已启用且健康的上游中选择出口。主要依据是延迟相对该线路平时水平的升幅和近期建连失败率，同时参考吞吐量与活跃会话数。已建立的会话沿用原出口。所有候选都故障时会报告错误。对明确绑定某个出口的流量，可以在「设置」里另选故障策略，初始行为是拒绝连接。

限速默认关闭。启用后，每个出口和中转机整体都可以分别设置上传、下载 Mbps 上限，新旧连接共享相应方向的额度。单条大下载要限制带宽时，应设置下载上限。

### 以切换备用域名为例

1. 在首页读取已接管 VPS 的配置。在「出口管理」选中原出口，选择备用域名，点击「选作连接域名」。TLS 名称按上游提供的参数填写。
2. 点击「预检 / 探活」，检查 DNS、协议握手、代理请求三项结果。通过后点「保存本地草稿」。此时新域名保存在电脑上。
3. 点击「应用到生产 VPS…」，核对预览里的**全部草稿变更**，再确认应用。Relay 静态校验配置、验证候选线路并持久化。成功后新连接使用新域名，旧会话排空。TCP 空闲期限为 5 分钟、UDP 为 2 分钟，最长排空 30 分钟。
4. 查看发布回执。若连接中断，可以点「核对上次应用」继续查询。发布失败时核对上一版状态，保留草稿以便修改。切换后可发起一条新连接，并在首页刷新出口状态和流量。

## 备份与更换 VPS

在「备份与迁移」选择离线安装材料目录、导出位置，输入并确认口令。备份包包含入口身份、上游凭据、备用域名、规则及顺序、启停状态、限速设置、Geo 数据和匹配的 Xray、Relay。程序使用 scrypt 派生密钥并以 AES-256-GCM 加密，导出后会重新解密校验清单和各文件的 SHA-256。请把备份包和口令分开保管。

源码仓库不分发内核和 Geo 数据。从源码构建且需要导出备份时，在可运行目标 Linux 二进制的 WSL 环境中准备匹配版本的 Xray 和两个 Geo 文件，再在 Windows 执行以下示例。路径换成自己的材料位置。脚本默认使用 Ubuntu 和 linux-x64。

```powershell
.\scripts\prepare-recovery-assets.ps1 -Xray .\materials\xray -GeoDirectory .\materials
```

脚本编译并核验 Relay，把清单与安装件放入本机私有目录。随后重新打包桌面端可将材料随程序携带。已携带完整材料的桌面程序可直接使用。

恢复时先点「仅校验恢复包」，再选择目标 VPS 的 SSH 登录方式。自动恢复支持同架构、采用 systemd 的 Linux 和普通 TCP VLESS REALITY 用户入口。目标机需有 root 登录、SSH/SFTP、Python 3、util-linux 和 GNU 基础工具。程序上传材料、静态校验、启动并验证线路。原客户端连接旧 IP 时可复制新地址链接，使用自有域名时按提示更新 DNS。最后从实际客户端复测公网入口。SSH 私钥留在本机，新机登录凭据单独指定。

## 项目结构与本机数据

| 目录 | 用途 |
| --- | --- |
| `src/VPSPanel.Desktop` | WPF Fluent 桌面界面 |
| `src/VPSPanel.Core` | SSH、配置与备份、Geo 解析，以及桌面与 Relay 共用的规则引擎 |
| `src/VPSPanel.Relay` | VPS 常驻调度服务，支持 TCP、UDP、双向限速和动态出口切换 |
| `src/VPSPanel.Guard` | 提交前检查暂存内容，推送前检查待发布提交的历史 |
| `tests/`、`scripts/` | 单元测试、隔离线路验收，以及构建和发布脚本 |

本机偏好、连接资料和草稿保存在 `%LOCALAPPDATA%\VPSPanel\`。记住的直连密码使用当前 Windows 用户的 DPAPI 加密。用 Git 克隆后，运行「构建与测试.cmd」即可启用项目的 Git 钩子。发布目录、私钥、迁移包和运行数据均应保存在版本管理之外。

完整规格、原机正式接管及回滚流程见 [VPS.md](VPS.md)。隔离验证入口见 [SSH 与迁移测试](tests/lab/test-phase2.ps1) 和 [双出口调度测试](tests/lab/test-stage3.ps1)。
