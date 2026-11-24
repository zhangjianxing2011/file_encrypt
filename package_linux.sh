#!/usr/bin/env bash
# ==============================================================================
# SecureVault - Linux / Ubuntu Desktop Packaging Script
# 生成适用于 Ubuntu / Debian / Fedora 等 Linux 发行版的桌面安装包与便携包
# ==============================================================================
set -euo pipefail

APP_NAME="SecureVault"
APP_VERSION=$(grep -m1 '^version' Cargo.toml | sed -E 's/version *= *"([^"]+)"/\1/' || echo "0.1.0")
ARCH="x64"

# 确定二进制文件路径
TARGET_BIN="${1:-}"
if [ -z "${TARGET_BIN}" ]; then
    if [ ! -f "target/release/securevault" ]; then
        echo "🔨 正在编译 Release 二进制文件..."
        cargo build --release
    fi
    TARGET_BIN="target/release/securevault"
fi

if [ ! -f "${TARGET_BIN}" ]; then
    echo "❌ 找不到二进制文件: ${TARGET_BIN}"
    exit 1
fi

STAGING_DIR="${APP_NAME}-Linux-${APP_VERSION}-${ARCH}"
TAR_NAME="${STAGING_DIR}.tar.gz"
PORTABLE_TAR="${APP_NAME}-Linux-portable.tar.gz"
STANDALONE_BIN="${APP_NAME}-Linux-${APP_VERSION}-${ARCH}"

echo "📦 正在打包 ${STAGING_DIR}..."
rm -rf "${STAGING_DIR}" "${TAR_NAME}" "${PORTABLE_TAR}"
mkdir -p "${STAGING_DIR}"

# 复制核心二进制
cp "${TARGET_BIN}" "${STAGING_DIR}/securevault"
chmod +x "${STAGING_DIR}/securevault"

# 复制图标与桌面启动文件
mkdir -p "${STAGING_DIR}/assets"
if [ -f "assets/icon.png" ]; then
    cp assets/icon.png "${STAGING_DIR}/assets/securevault.png"
fi
if [ -f "assets/securevault.desktop" ]; then
    cp assets/securevault.desktop "${STAGING_DIR}/securevault.desktop"
fi
if [ -f "README.md" ]; then
    cp README.md "${STAGING_DIR}/README.md"
fi

# 生成一键安装脚本 install.sh
cat > "${STAGING_DIR}/install.sh" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_BIN="${SCRIPT_DIR}/securevault"
DESKTOP_SRC="${SCRIPT_DIR}/securevault.desktop"
ICON_SRC="${SCRIPT_DIR}/assets/securevault.png"

if [ ! -f "${APP_BIN}" ]; then
    echo "❌ 错误: 找不到可执行文件 ${APP_BIN}"
    exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
    # 系统级安装
    BIN_DIR="/usr/local/bin"
    APP_DIR="/usr/share/applications"
    ICON_DIR="/usr/share/icons/hicolor/256x256/apps"
else
    # 用户级安装
    BIN_DIR="${HOME}/.local/bin"
    APP_DIR="${HOME}/.local/share/applications"
    ICON_DIR="${HOME}/.local/share/icons/hicolor/256x256/apps"
fi

echo "🚀 开始安装 SecureVault..."
mkdir -p "${BIN_DIR}" "${APP_DIR}" "${ICON_DIR}"

# 1. 安装二进制文件
cp "${APP_BIN}" "${BIN_DIR}/securevault"
chmod +x "${BIN_DIR}/securevault"
echo "✅ 已安装二进制至: ${BIN_DIR}/securevault"

# 2. 安装图标
if [ -f "${ICON_SRC}" ]; then
    cp "${ICON_SRC}" "${ICON_DIR}/securevault.png"
    echo "✅ 已安装应用图标至: ${ICON_DIR}/securevault.png"
fi

# 3. 安装 Desktop 菜单项
if [ -f "${DESKTOP_SRC}" ]; then
    sed -e "s|^Exec=.*|Exec=${BIN_DIR}/securevault %F|" \
        -e "s|^Icon=.*|Icon=${ICON_DIR}/securevault.png|" \
        "${DESKTOP_SRC}" > "${APP_DIR}/securevault.desktop"
    chmod +x "${APP_DIR}/securevault.desktop"
    echo "✅ 已安装桌面项至: ${APP_DIR}/securevault.desktop"
fi

# 4. 刷新桌面数据库与图标缓存
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "${APP_DIR}" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$(dirname "${ICON_DIR}")/.." 2>/dev/null || true
fi

echo ""
echo "🎉 SecureVault 安装完成！"
echo "   - 桌面启动: 在应用程序菜单/启动器中搜索 'SecureVault' 打开"
echo "   - 命令行运行: 直接运行 'securevault --help' 或 'securevault gui'"
if [ "$(id -u)" -ne 0 ]; then
    if [[ ":$PATH:" != *":${HOME}/.local/bin:"* ]]; then
        echo "💡 提示: 请确保 ${HOME}/.local/bin 在您的 PATH 环境变量中："
        echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
fi
EOF
chmod +x "${STAGING_DIR}/install.sh"

# 生成卸载脚本 uninstall.sh
cat > "${STAGING_DIR}/uninstall.sh" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
    BIN_DIR="/usr/local/bin"
    APP_DIR="/usr/share/applications"
    ICON_DIR="/usr/share/icons/hicolor/256x256/apps"
else
    BIN_DIR="${HOME}/.local/bin"
    APP_DIR="${HOME}/.local/share/applications"
    ICON_DIR="${HOME}/.local/share/icons/hicolor/256x256/apps"
fi

echo "🧹 正在卸载 SecureVault..."
rm -f "${BIN_DIR}/securevault"
rm -f "${APP_DIR}/securevault.desktop"
rm -f "${ICON_DIR}/securevault.png"

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "${APP_DIR}" 2>/dev/null || true
fi

echo "✅ SecureVault 已成功卸载。"
EOF
chmod +x "${STAGING_DIR}/uninstall.sh"

# 打包 tar.gz
echo "🗜️ 正在压缩成 ${TAR_NAME}..."
tar -czf "${TAR_NAME}" "${STAGING_DIR}"
cp "${TAR_NAME}" "${PORTABLE_TAR}"

# 复制一份独立二进制文件供直接下载
cp "${TARGET_BIN}" "${STANDALONE_BIN}"
chmod +x "${STANDALONE_BIN}"

echo "================================================================="
echo "✅ Linux 安装包打包完成！"
echo "   - 安装包目录: ${STAGING_DIR}"
echo "   - 便携压缩包: ${TAR_NAME} / ${PORTABLE_TAR}"
echo "   - 单文件二进制: ${STANDALONE_BIN}"
echo ""
echo "💡 Ubuntu / Linux 用户安装说明："
echo "   1. 解压: tar -xzf ${TAR_NAME}"
echo "   2. 安装: cd ${STAGING_DIR} && ./install.sh (或 sudo ./install.sh)"
echo "   3. 免安装运行: ./${STAGING_DIR}/securevault"
echo "================================================================="
