# SecureVault (跨平台文件夹安全锁 - 免安装绿色版)

高性能跨平台（Windows & macOS）文件夹原地加密工具。基于 **Rust** 开发，结合 **Argon2id + HKDF + AES-256-GCM** 构建。支持原生图形界面（GUI）与命令行界面（CLI）。

---

## 核心特性

1. **完全免安装 / 绿色便携**：
   - **Windows**：单个 `.exe` 二进制文件，无注册表依赖，随拷随用。
   - **macOS**：提供绿色免安装的 `SecureVault.app` 应用程序包及打包脚本，支持解压即用。
2. **左侧管理面板与文件展示**：
   - 左侧常驻受保护文件夹列表，自动持久化记录用户添加的保险箱。
   - **已加密状态**：展示 `.vault_data` 中的随机 UUID 密文数据块及加密大小，原始文件名和目录结构被强加密混淆，彻底防窥。
   - **解密明文状态**：展示文件夹内的真实文件清单、子目录结构及占用大小。
3. **关闭时防遗漏重新加密提示（支持中文密钥）**：
   - 监听窗口关闭事件，若检测到有处于“解密明文”状态的文件夹，自动弹出安全确认弹窗。
   - 用户可输入新的加密密钥（**完全支持中文字符、字母、数字、特殊符号**），一键重新加密后安全退出。
   - 内置系统级中文字体回退加载，保证界面汉字与中文密码输入清晰显示，杜绝方框问号。
4. **完全原地操作**：
   - 保持在原文件夹内操作，不依赖挂载额外虚拟盘符或卷轴。
   - 锁定状态下，原始文件和子目录结构全部被清空粉碎，只留加密混淆数据与密文索引。
5. **安全防撞库 & 抗暴力破解**：
   - **Argon2id**（内存硬度参数 64MB，3 次迭代，4 通道并行），强力抗击 GPU/ASIC 并行碰撞。
   - **HKDF-SHA256** 派生独立的索引密钥、数据块密钥与验证 HMAC。
   - **常数时间校验**，防止时间侧信道分析。
6. **高性能流式加密与多线程并行**：
   - 使用 **Rayon** 线程池多线程并行处理文件。
   - 采用 1MB 流式分块，避免大文件内存暴增。
   - 支持 CPU AES-NI 原生硬件加速。

---

## 免安装运行与打包说明

### Windows 免安装使用
1. 编译生成产物：`target\release\securevault.exe`。
2. 该文件为单文件独立程序，无需运行任何安装器，双击即可直接打开图形界面，也可直接通过命令行调用。

### macOS 安装镜像与免安装包
macOS 支持一键打包为 `.dmg` 拖拽安装镜像及 `.app` 绿色免安装包：
1. **一键生成 macOS 安装包与镜像**：
   ```bash
   chmod +x ./package_mac.sh
   ./package_mac.sh
   ```
   执行后将自动生成：
   - `SecureVault.dmg`：标准的 macOS 拖拽安装镜像（内置 `/Applications` 替身）。
   - `SecureVault.app`：标准的 macOS 应用程序包目录。
   - `SecureVault-macOS-portable.zip`：可直接发给其他用户的免安装绿色压缩包。

2. **macOS 隔离属性（Gatekeeper）处理**：
   若未在苹果官方付费签名，从网络下载的 `.app` 会被 macOS 标记隔离。只需采用以下任一方式即可正常打开：
   - **图形操作**：按住 `Control` 键（或右键）点击 `SecureVault.app`，选择【打开】，在弹出窗口中点击【打开】即可（仅需首次操作一次）。
   - **终端命令**：运行 `xattr -cr /Applications/SecureVault.app`（或对应 app 路径）清除隔离属性。

### GitHub Actions 自动打包（CI/CD）
项目已配置自动化构建工作流（`.github/workflows/build-and-release.yml`）：
- **日常编译产物**：向 `main` 分支提交代码或手动触发（`Actions -> Run workflow`），系统将自动完成 Windows（`.exe`）与 macOS（Universal 通用架构 `.dmg`）的打包，可在该次运行的 **Artifacts** 区域直接下载。
- **自动化发布 Release**：推送版本 Tag（如 `v0.1.0`）时，将自动创建 GitHub Release 并上传以下资产：
  - `SecureVault-Windows-x64.exe`（Windows 64位单文件可执行程序）
  - `SecureVault-Windows-x64.zip`（包含可执行程序及说明文档）
  - `SecureVault-macOS.dmg`（macOS 通用架构安装镜像，同时支持 Apple Silicon M系列与 Intel Mac）
  - `SecureVault-macOS-portable.zip`（macOS 免安装绿色便携包）

---

## 图形界面使用指南

1. **启动界面**：
   - Windows 直接双击 `securevault.exe`。
   - macOS 双击 `SecureVault.app`。
2. **左侧管理栏**：
   - 点击【➕ 添加】选择需要管理的文件夹。
   - 随时查看各文件夹的加密/解密状态。
   - 展开选中项查看密文块或明文文件。
3. **右侧操作区**：
   - **🔒 加密锁定**：设置新密码（支持中文密钥）并原地加密。
   - **🔓 解密还原**：输入密码验证并还原全部原始文件。
   - **🔑 修改密码**：快速更新索引密文与密钥。
   - **ℹ️ 详细信息**：查看容量、文件数等元数据详情。
4. **安全退出提示**：
   - 当点击窗口右上角关闭按钮时，如果当前存在明文文件夹，系统将弹出【⚠️ 退出安全保护确认】窗口。
   - 用户可输入新的中文密码一键加密并退出，防止遗漏明文造成泄密。

---

## 命令行（CLI）指令速查

- **启动 GUI**：
  ```bash
  securevault gui
  ```
- **加密锁定**：
  ```bash
  securevault lock /path/to/folder
  # 或者通过 -p 指定密码（支持中文）：
  securevault lock /path/to/folder -p "我的中文密码123"
  ```
- **解密还原**：
  ```bash
  securevault unlock /path/to/folder
  # 或者指定密码：
  securevault unlock /path/to/folder -p "我的中文密码123"
  ```
- **查看状态**：
  ```bash
  securevault status /path/to/folder
  ```
- **修改密码**：
  ```bash
  securevault change-password /path/to/folder
  ```
