# SecureVault (跨平台文件夹安全锁 - 免安装绿色版)

高性能跨平台（Windows, macOS & Linux / Ubuntu Desktop）文件夹原地加密工具。基于 **Rust** 开发，结合 **Argon2id + HKDF + AES-256-GCM** 构建。支持原生图形界面（GUI）与全功能命令行界面（CLI）。

---

## 核心特性

1. **完全免安装 / 绿色便携**：
   - **Windows**：单个 `.exe` 二进制文件，无注册表依赖，随拷随用。
   - **macOS**：提供绿色免安装的 `SecureVault.app` 应用程序包与 `.dmg` 拖拽镜像，支持解压即用。
   - **Linux / Ubuntu Desktop**：提供绿色免安装 `.tar.gz` 压缩包与独立二进制，附带一键式 `install.sh` 快速集成桌面启动器图标与标准 XDG 菜单。
2. **左侧管理面板与文件展示**：
   - 左侧常驻受保护文件夹列表，跨平台自动持久化记录用户添加的保险箱（Windows `%APPDATA%`, macOS `~/Library/Application Support`, Linux `$XDG_CONFIG_HOME` 或 `~/.config`）。
   - **已加密状态**：展示 `.vault_data` 中的随机 UUID 密文数据块及加密大小，原始文件名和目录结构被强加密混淆，彻底防窥。
   - **解密明文状态**：展示文件夹内的真实文件清单、子目录结构及占用大小。
3. **全功能命令行（CLI）与批处理支持**：
   - 支持批量加密（`lock`）、批量解密（`unlock`）、批量追加（`append`）与批量状态检测（`status`）。
   - 提供保险箱元数据深度探查（`info` / `inspect`）与常驻管理列表操作（`list` / `vaults`, `add`, `remove`）。
   - 在 Linux / SSH 无显示服务环境下无参数启动时自动优雅提示并展示 CLI 帮助，不抛出窗口崩溃。
4. **关闭时防遗漏重新加密提示（支持中文密钥）**：
   - 监听窗口关闭事件，若检测到有处于“解密明文”状态的文件夹，自动弹出安全确认弹窗。
   - 用户可输入新的加密密钥（**完全支持中文字符、字母、数字、特殊符号**），一键重新加密后安全退出。
   - 内置全平台系统级中文字体回退加载（Windows: 微软雅黑/宋体；macOS: PingFang SC/苹方；Ubuntu/Linux: Noto Sans CJK/文泉驿），保证界面汉字与中文密码输入清晰显示，杜绝方框问号。
5. **完全原地操作**：
   - 保持在原文件夹内操作，不依赖挂载额外虚拟盘符或卷轴。
   - 锁定状态下，原始文件和子目录结构全部被清空粉碎，只留加密混淆数据与密文索引。
6. **安全防撞库 & 抗暴力破解**：
   - **Argon2id**（内存硬度参数 64MB，3 次迭代，4 通道并行），强力抗击 GPU/ASIC 并行碰撞。
   - **HKDF-SHA256** 派生独立的索引密钥、数据块密钥与验证 HMAC。
   - **常数时间校验**，防止时间侧信道分析。
7. **高性能流式加密与多线程并行**：
   - 使用 **Rayon** 线程池多线程并行处理文件。
   - 采用 1MB 流式分块并复用内存缓冲区，避免大文件内存暴增。
   - 原文件支持原地覆写安全粉碎（包含 fsync 物理落盘）。
   - 支持 CPU AES-NI 原生硬件加速。
8. **完整性校验与解密故障自动回滚**：
   - 采用全文件 SHA-256 哈希与 AES-256-GCM 认证标签进行端到端双重完整性校验。
   - 解密过程中若检测到密文受损或非法篡改，自动触发安全回滚并清理已释放文件，严防明文碎片残留泄露。
9. **继续加密新增文件**：
   - 将新文件放入已锁定的文件夹后，使用原密码执行【继续加密】，仅加密本次新增文件，保留已有密文数据块。
   - 支持同步新增空目录。显示新增文件数量为 0 时，空目录仍可能已经同步。
   - 新放入的文件在执行成功前仍是明文，不会因为文件夹显示“已加密”而自动受到保护。
   - 新文件与原有加密文件的相对路径冲突时，整批操作会停止，不覆盖原有文件；请先重命名或移走冲突的新文件。
   - 如果提示索引已更新但明文清理失败，新增文件已经加入保险箱，残留明文仍需处理；不要直接重试或解密。请先把残留明文移至保险箱外的安全位置，再进行解密核对。异常退出或断电后也应先检查残留文件；此功能不保证所有断电场景下的自动恢复。
   - 操作锁文件 `.vault_operation.lock` 用于阻止同一保险箱的并发操作，不存储密码；不要在操作期间手动删除它。
   - 处理中请勿改动文件或目录。Windows 会限制其他进程写入或删除正在处理的源文件；Unix 使用协作锁，不能阻止所有外部修改。

---

## 🛡️ 存储安全必读：强烈建议在全盘加密环境下使用

> [!IMPORTANT]
> **关键安全声明**：为了防范加密前的数据或已粉碎的明文被专业硬件手段还原，**强烈建议在已启用全盘加密（Windows BitLocker、macOS FileVault 或 Linux LUKS）的磁盘分区中使用本工具**。
> 若在普通未加密的固态硬盘（SSD）上直接使用，即便本软件已执行覆写粉碎，由于现代闪存主控的物理特性，加密前的原始明文仍有可能在底层物理芯片中残留。

### 1. 软件层“安全粉碎”的局限性与 SSD 硬件特性
本软件在加密锁定时，会对原始文件执行单次写 0 覆写（Zero-fill），并调用系统底层的物理落盘指令（`sync_all` / `fsync`），最后解除文件引用。在传统的**机械硬盘（HDD）**上，这足以确保常规及专业数据恢复软件无法找回文件。

然而，在现代**固态硬盘（SSD / NVMe / UFS）与闪存介质**上，存储机制存在本质不同：
- **磨损均衡（Wear-Leveling）与闪存转换层（FTL）**：SSD 闪存颗粒不能直接原地覆盖写入，必须“先擦除整块（Block）再写入页（Page）”。为了保护颗粒寿命，SSD 主控芯片（FTL）会将覆写的“全 0”数据分配写入到**全新的物理闪存块**，并将逻辑地址重映射；
- **旧物理块的残留隐患**：原先存放“加密前真实原文”的**旧物理块只是被标记为无效（Invalid/Stale）**，并不会立刻在物理上清空。直到 SSD 触发垃圾回收（Garbage Collection）且后台执行了真正的擦除操作之前，这些旧物理块依然驻留在闪存芯片中；
- **芯片级硬件取证（Chip-off / PC-3000）**：在未开启全盘加密的环境下，专业取证机构通过硬件工具直接脱焊闪存颗粒或绕过 FTL 映射表，理论上仍有可能直接读取出旧物理块中的明文碎片。

### 2. 操作系统的旁路缓存与快照风险
除了底层闪存特性外，操作系统在日常运行时也可能保留明文痕迹：
- **Windows 卷影副本（VSS / 系统还原点）**：系统自动创建的历史快照可能保留加密前的整份明文文件；
- **应用程序临时缓存**：办公软件（Office/WPS 等）在编辑期间生成的 `~$xxx.docx`、`AppData\Local\Temp` 临时副本；
- **缩略图数据库**：图片与视频文件可能残留在 Windows `thumbcache.db` 缓存中；
- **虚拟内存与休眠**：内存中曾预览过的内容可能被操作系统换出到 `pagefile.sys`（页面文件）或 `hiberfil.sys`（休眠文件）。

### 3. 全盘加密（FDE）的协同防护威力：为什么能彻底杜绝残留？
当你在开启了系统级全盘加密的磁盘分区中使用本工具时：
- **Windows**：开启 **BitLocker**（内置盘或移动硬盘 BitLocker To Go）；
- **macOS**：开启 **FileVault**（内置盘或外接 APFS 加密卷）；
- **Linux**：开启 **LUKS** 全盘加密分区。

**协同效应（双重加密 / 纵深防御）**：
在全盘加密环境下，**整块物理介质上的每一个扇区（包括 SSD 磨损均衡产生的所有旧物理块、未分配空间、系统还原点、临时目录与虚拟内存）在硬件底层芯片上全都是高强度的底层密文**。
即使物理闪存块尚未被垃圾回收擦除，或者芯片被脱焊读取，没有系统全盘加密的主密钥，任何人都只能读取到一堆无意义的乱码。此时，本软件的应用层加密粉碎与系统底层全盘加密形成完美的互补闭环，**从物理介质层面彻底阻断了任何还原加密前原文的可能性**。

---

## 操作系统版本支持说明 (Windows, macOS & Linux)

| 平台 / 运行模式 | 最低系统版本要求 | 架构要求 | 关键限制与底层依赖说明 |
| :--- | :--- | :--- | :--- |
| **Windows（GUI 图形界面）** | **Windows 10**（64位，1607+）<br>或 **Windows Server 2016** 及以上 | **64 位 (x64)** | 内置基于 `eframe` + `wgpu` 的现代图形栈，依赖 **DirectX 12**、现代 Vulkan 与 DXGI 1.4+。<br>❌ *Windows 7 / 8 / 8.1 / Server 2012 R2 因缺少 DirectX 12 驱动支持，无法运行 GUI 版本。* |
| **macOS（GUI 图形界面）** | **macOS 11.0 (Big Sur)** 及更高版本 | **Apple Silicon (M1~M6 全系)** | 提供原生 `.app` 与 `.dmg` 镜像，已完成 Ad-hoc 签名与隔离优化。<br>❌ *不提供老旧 Intel x86_64 Mac 架构支持。* |
| **Linux / Ubuntu Desktop（GUI 图形界面）** | **Ubuntu 20.04 / 22.04 / 24.04 LTS**<br>Debian 11/12, Fedora 36+, Arch Linux 等 | **64 位 (x64 / x86_64)** | 支持原生 **X11 与 Wayland**（GNOME, KDE 等桌面环境）；内置主流中文字体回退（Noto Sans CJK、文泉驿等）。依赖基础 GTK3/XCB 运行时环境。 |
| **全平台命令行模式（CLI）** | 同各平台基线版本<br>*(Linux 支持无显示环境/Headless 模式)* | **64 位 (x64)** | 在 Linux / SSH 无显示服务环境下无参数启动时，自动友好提示并回退至 CLI 命令帮助，杜绝闪退崩溃。 |

> [!NOTE]
> * **32 位支持**：不支持任何 32 位（x86）系统。
> * **Linux / Ubuntu 依赖**：各主流发行版默认已预装所需基础库。若在极精简 Linux 环境中运行 GUI，只需安装常用库（如 `sudo apt install libgtk-3-0 libx11-6 libxcb-render0`）。

---

## 快速开始（获取与运行）

SecureVault 为**完全免安装的绿色便携软件**，不写注册表、不驻留后台服务，下载即可随拷随用。

### Windows 用户使用方法
1. **获取软件**：
   * 下载单文件版 `SecureVault-Windows-<版本号>-x64.exe`（如 `SecureVault-Windows-1.0.9-x64.exe`），或下载并解压 `SecureVault-Windows-<版本号>-x64.zip`。
2. **运行使用**：
   * **图形界面**：直接双击 `SecureVault-Windows-<版本号>-x64.exe`（或重命名后的 `securevault.exe`）即可打开窗口。
   * **命令行使用**：在软件所在目录空白处按住 `Shift + 鼠标右键`，选择【在此处打开 PowerShell 窗口】或【在终端中打开】，直接输入 `.\SecureVault-Windows-<版本号>-x64.exe <命令>`（亦可将程序放入系统的 PATH 环境变量目录中简写为 `securevault`）。

### Ubuntu / Linux Desktop 用户使用方法

#### 1. 一键解压与系统级/用户级安装（推荐）
1. 从 GitHub Releases 下载最新安装包 `SecureVault-Linux-<版本号>-x64.tar.gz`。
2. 打开终端解压并进入目录：
   ```bash
   tar -xzf SecureVault-Linux-*.tar.gz
   cd SecureVault-Linux-*-x64
   ```
3. 执行一键安装脚本（自动安装二进制、高清应用图标及桌面启动菜单项）：
   ```bash
   # 系统全局安装（面向所有用户，推荐）：
   sudo ./install.sh

   # 或当前用户安装（免 sudo 权限，安装至 ~/.local/bin）：
   ./install.sh
   ```
4. **启动使用**：
   - **桌面启动**：在 Ubuntu 应用程序启动器（按 Super/Win 键）中搜索 **“SecureVault”** 或 **“文件保险箱”**，点击即可打开原生图形界面。
   - **终端运行**：直接在任意终端中执行 `securevault --help` 或 `securevault gui`。

#### 2. 免安装绿色便携运行（直接运行）
若无需集成桌面图标，可直接解压后运行文件夹内的可执行文件：
```bash
./securevault gui              # 启动图形界面
./securevault lock /path/dir   # 命令行加密
```
亦可直接下载单文件独立二进制 `SecureVault-Linux-<版本号>-x64`：
```bash
chmod +x SecureVault-Linux-*-x64
./SecureVault-Linux-*-x64 --help
```

---

### macOS 用户使用方法与安装问题解决

#### 1. 正确安装流程（避免“应该推出磁盘映像”提示）
1. 从 GitHub Releases 下载 `SecureVault-macOS-<版本号>.dmg`（或 `SecureVault.dmg`）镜像文件。
2. 双击打开 `SecureVault.dmg`。
3. **将 `SecureVault.app` 图标拖入右侧的 `Applications`（应用程序）文件夹中**。
4. **【关键步骤】** 拖拽复制完成后，请在访达（Finder）侧边栏或桌面上，右键点击 `SecureVault` 磁盘镜像图标选择**【推出】（Eject）**。
   * ⚠️ **切勿直接在 DMG 磁盘卷里双击运行！** macOS 会检测到未安装在本地硬盘上而触发安全阻止，并弹出 *“你应该推出磁盘映像”*。

---

#### 2. 常见问题：提示“SecureVault.app 已损坏，无法打开。你应该推出磁盘映像。”

从 GitHub 或浏览器下载的未公证（未向 Apple 每年缴纳 $99 开发者认证）第三方开源软件，会被 macOS Gatekeeper 自动附加系统隔离标记（`com.apple.quarantine`），导致系统误报“文件已损坏”。**这并非文件损坏，只需一次性解除隔离标记即可：**

##### 方案 A：终端一键解除隔离（最快最彻底，强烈推荐）
1. 按快捷键 `Command + 空格` 调出聚焦搜索（Spotlight），输入 `终端` 或 `Terminal` 并回车打开。
2. 复制并粘贴以下命令，然后按回车执行：
   ```bash
   xattr -cr /Applications/SecureVault.app
   ```
   *注：如果系统提示无权限，请使用管理员权限执行（需输入 Mac 登录密码）：*
   ```bash
   sudo xattr -rd com.apple.quarantine /Applications/SecureVault.app
   ```
3. 执行完成后关闭终端，直接在【访达】->【应用程序】中双击 `SecureVault.app` 即可正常运行！

##### 方案 B：右键打开或系统设置放行（适用于“无法验证开发者”提示）
* **右键打开**：在【应用程序】中找到 `SecureVault.app`，按住键盘 `Control` 键同时鼠标点击（或直接鼠标右键），在弹出菜单中选择【打开】，并在弹窗中点击【仍要打开】或【打开】。
* **系统设置放行**：双击被阻止后，打开 Mac【系统设置】->【隐私与安全性】，向下滚动到安全性区域，点击【仍要打开】。

##### 方案 C：使用免安装绿色便携包（免 DMG 挂载）
* 若不想处理 DMG 镜像挂载，可直接在 GitHub Release 页面下载免安装绿色包 **`SecureVault-macOS-portable.zip`**。
* 下载后直接解压到任意文件夹（例如【下载】或【桌面】），按方案 B 右键【打开】即可使用。若解压后仍提示损坏，在终端对解压后的路径执行 `xattr -cr /路径/SecureVault.app` 即可。

---

## 图形界面使用指南

1. **启动界面**：
   - Windows 直接双击 `securevault.exe`。
   - macOS 双击 `SecureVault.app`。
   - 也可通过命令行直接运行 `securevault` 或 `securevault gui`。
2. **左侧管理栏与批量操作**：
   - 点击【➕ 添加】选择本地文件夹进行管理（**支持在系统弹窗中按住 Shift / Cmd 多选一次性添加多个项目**）。
   - **🔒 批量加密**：当有多个未锁定的项目时，点击左侧顶部【🔒 批量加密】，可一键勾选多个项目并统一设置密码进行批量加密，进度实时刷新，各个项目加密完成后立即变更为已加密锁定状态。
   - **🔓 批量解密**：点击【🔓 批量解密】可对选中的多个已加密项目输入密钥批量解密还原。
   - 随时查看各文件夹的加密/解密状态，进行中的项目实时显示动态进度徽章（如 `🔄 解密中 15/45`）。
   - 展开选中项查看密文块或明文文件目录树。
   - 支持从管理列表移除记录或在系统文件管理器中打开。
3. **右侧操作区与实时解密反馈**：
   - **🔒 加密锁定**：设置新密码（支持中文字符、字母、数字、特殊符号，支持一键生成 64 位高熵随机密码）并执行原地加密。
   - **⚡ 逐文件实时解密动态（无需等待全部完成）**：解密还原时，系统在后台每解密一个文件，界面即时更新进度条、完成百分比与已解密文件计数（`已解密: X / Y 个文件`），并在【⚡ 实时解密文件清单】中即时逐条列出已还原的文件及体积，左侧目录树与徽章同步动态更新，全程透明可见。
   - **继续加密**：选中已锁定文件夹，进入【🔒 加密锁定】标签，输入原密码并点击【继续加密】。无需先解密，也无需设置新密码；完成后显示本次新增文件数量。没有新增文件时会明确提示。
   - **🔓 解密还原**：输入对应密码验证并还原全部原始文件与子目录结构。
   - **ℹ️ 详细信息**：查看容量、文件/加密块数量、加密状态等详细元数据。
   - **更换密码说明**：若需更换加密密码，只需先在【🔓 解密还原】标签页解密还原文件夹，再切换至【🔒 加密锁定】重新设置新密码加密即可。
4. **安全退出提示**：
   - 当点击窗口右上角关闭按钮时，如果当前存在明文文件夹，系统将弹出【⚠️ 退出安全保护确认】窗口。
   - 用户可输入新的密码一键加密所有明文文件夹后安全退出，防止遗漏明文造成泄密。

---

## 命令行（CLI）指令速查

SecureVault 在 Windows、macOS 与 Linux / Ubuntu 终端中均提供一致的全功能命令行体验：
- **Windows**：在 PowerShell / CMD 中执行 `.\securevault.exe <命令>`（或配置 PATH 后直接 `securevault <命令>`）。
- **macOS / Linux**：在 Terminal 中执行 `securevault <命令>`（或 `./securevault <命令>`）。

SecureVault 命令行默认采用**安全交互式密码输入**（输入时不显示字符，全面支持中文字符与高熵随机密码），**彻底避免密码残留在终端命令历史（Bash/Zsh/PowerShell）、系统任务管理器进程列表或操作系统审计日志中**。

### 1. 常用命令清单

| 命令格式 | 功能说明 | 密码机制 / 参数说明 |
| :--- | :--- | :--- |
| `securevault gui` | 启动原生图形界面（无参数运行且在图形桌面下时默认启动 GUI） | 界面图形化操作 |
| `securevault lock <路径1> [路径2...]` | 将一个或多个文件夹原地加密锁定为保险箱（支持批量） | 控制台安全交互输入并二次确认（支持 `--hint`，脚本可用 `-p`） |
| `securevault unlock <路径1> [路径2...]` | 将一个或多个已锁定的保险箱原地解密还原（支持批量） | 控制台安全交互输入（脚本可用 `-p`） |
| `securevault append <路径1> [路径2...]` | 为已锁定的保险箱继续加密新增文件/同步新目录（支持批量） | 控制台安全交互输入原密码（安全考虑不接收 `-p` 参数） |
| `securevault status <路径1> [路径2...]` | 查看指定文件夹当前是处于锁定（密文）还是解锁（明文）状态 | 无需密码，支持批量检测 |
| `securevault info <路径>`<br>*(别名: `inspect`)* | 深度探查保险箱元数据（体积、文件数、分块数、创建时间与密码提示等） | 无需密码 |
| `securevault list`<br>*(别名: `vaults`)* | 列出当前系统记录的所有常驻保险箱及实时锁定状态 | 无需密码 |
| `securevault add <路径> [-n, --name <别名>]` | 将指定文件夹添加至系统的常驻保险箱管理列表 | 无需密码 |
| `securevault remove <路径或别名>` | 从常驻保险箱列表中移除指定文件夹（不删除本地文件） | 无需密码 |
| `securevault --help` | 查看完整帮助文档与所有子命令详细参数 | 无需密码 |

---

### 2. 命令详细说明与交互式使用示例

#### ① 单个与批量加密锁定 (`lock`)
```bash
# 单个文件夹加密：
securevault lock /path/to/my_folder

# 批量加密多个文件夹（支持统一设置密码，逐个处理）：
securevault lock /data/project1 /data/project2 /data/project3

# 附带密码提示（Hint）加密：
securevault lock /path/to/my_folder --hint "常用八位密码"
```
执行后将提示交互式设置密码并确认（字符不回显）：
```text
💡 提示: 密码支持中文、字母、数字及特殊符号。采用零知识高强加密，无密码找回机制，请务必牢记！
Enter new password: [输入密码，无回显]
Confirm password:   [再次确认密码]
```

#### ② 单个与批量解密还原 (`unlock`)
```bash
# 单个文件夹解密：
securevault unlock /path/to/my_folder

# 批量解密多个文件夹：
securevault unlock /data/project1 /data/project2
```
若保险箱加密时留有密码提示（Hint），系统会在提示输入密码前友好显示该提示信息。

#### ③ 继续加密新增文件 (`append`)
```bash
# 将新放入已锁定文件夹中的文件进行增量加密同步：
securevault append /path/to/locked_folder

# 批量增量同步多个保险箱：
securevault append /data/project1 /data/project2
```
处理新增文件并同步新增空目录，已有密文数据块保持不变；相对路径冲突时停止，不覆盖。

#### ④ 检查锁定状态 (`status`)
```bash
securevault status /path/folder1 /path/folder2
```
输出示例：
```text
🔒 Folder is LOCKED: /path/folder1
🔓 Folder is UNLOCKED: /path/folder2
```

#### ⑤ 深度查看保险箱元数据 (`info` / `inspect`)
```bash
securevault info /path/to/my_folder
```
输出示例：
```text
📦 Vault Information: /path/to/my_folder
  Status:           🔒 LOCKED (Encrypted)
  Encrypted Size:   142.50 MB
  Ciphertext Blocks: 18 files in .vault_data
  Created Time:     2026-11-24 09:15:20
  Password Hint:    常用工作密钥
```

#### ⑥ 管理常驻跟踪列表 (`list`, `add`, `remove`)
```bash
# 查看所有已记录的保险箱：
securevault list

# 添加新的保险箱并指定别名：
securevault add /data/confidential --name "机密档案"

# 从跟踪列表中移除（安全操作，不触碰任何本地文件）：
securevault remove "机密档案"
# 或按路径移除：
securevault remove /data/confidential
```

#### ⑦ 更换密码流程（交互式）
如需更换密码，遵循“先解密还原、再重新加密锁定”的安全交互式流程：
```bash
# 步骤 1：解密还原（交互式输入原密码）
securevault unlock /path/to/folder

# 步骤 2：重新加密（交互式设置并确认新密码）
securevault lock /path/to/folder
```

---

### 3. Linux 无显示环境（Headless / SSH / Server）支持

在没有 X11 / Wayland 图形桌面服务（例如云服务器、远程 SSH 会话或 Docker 容器）中运行 `securevault` 时：
- 程序会自动检测 `DISPLAY` 与 `WAYLAND_DISPLAY` 环境变量。
- 若未提供子命令，系统不会尝试初始化图形栈而崩溃，而是友好输出提示并展示命令行帮助信息：
  ```text
  ℹ️  Notice: No graphical display detected (DISPLAY or WAYLAND_DISPLAY not set).
  Running in CLI mode. Use 'securevault --help' to see all available subcommands.
  ```

---

### 4. 自动化脚本参数说明（谨慎使用）

针对无人值守 CI/CD 或自动化测试场景，`lock` 与 `unlock` 命令支持通过 `-p, --password` 传入密码：
```bash
# 仅建议在自动化脚本环境中使用
securevault lock /path/to/folder -p "测试临时密码123"
securevault unlock /path/to/folder -p "测试临时密码123"
```

> [!WARNING]
> **安全警示**：日常使用**强烈推荐使用默认的交互式输入**。切勿在日常交互中使用 `-p / --password` 传递重要密码，否则密码将直接以明文形式暴露在系统命令行历史记录、任务管理器详情列以及安全审计日志中。`append`（继续加密）命令出于安全审计考虑已硬性禁止 `-p` 参数。
