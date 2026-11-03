#!/usr/bin/env bash
# ==============================================================================
# SecureVault - macOS App Bundle & DMG Packager
# 生成 macOS 应用程序包 SecureVault.app、DMG 安装镜像及免安装 ZIP
# ==============================================================================
set -euo pipefail

APP_NAME="SecureVault"
BUNDLE="${APP_NAME}.app"
CONTENTS="${BUNDLE}/Contents"
MACOS="${CONTENTS}/MacOS"
RESOURCES="${CONTENTS}/Resources"

# 自动从 Cargo.toml 提取版本号
APP_VERSION=$(grep -m1 '^version' Cargo.toml | sed -E 's/version *= *"([^"]+)"/\1/' || echo "0.1.0")

# 确定二进制文件路径（优先使用传入参数，如通用二进制 target/universal/securevault）
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

echo "📦 正在构建 ${BUNDLE} (版本: ${APP_VERSION})..."
rm -rf "${BUNDLE}"
mkdir -p "${MACOS}"
mkdir -p "${RESOURCES}"

# 复制二进制文件并设置可执行权限
cp "${TARGET_BIN}" "${MACOS}/securevault"
chmod +x "${MACOS}/securevault"

# 移除隔离属性，防止 macOS Gatekeeper 报 "已损坏，无法打开"
xattr -cr "${MACOS}/securevault" 2>/dev/null || true

# 生成 macOS 原生高清 ICNS 图标
if [ -f "assets/icon.png" ]; then
    echo "🎨 正在生成 macOS 高清图标..."
    ICONSET="${APP_NAME}.iconset"
    mkdir -p "${ICONSET}"
    if command -v sips >/dev/null 2>&1 && command -v iconutil >/dev/null 2>&1; then
        sips -z 16 16     assets/icon.png --out "${ICONSET}/icon_16x16.png" >/dev/null 2>&1 || true
        sips -z 32 32     assets/icon.png --out "${ICONSET}/icon_16x16@2x.png" >/dev/null 2>&1 || true
        sips -z 32 32     assets/icon.png --out "${ICONSET}/icon_32x32.png" >/dev/null 2>&1 || true
        sips -z 64 64     assets/icon.png --out "${ICONSET}/icon_32x32@2x.png" >/dev/null 2>&1 || true
        sips -z 128 128   assets/icon.png --out "${ICONSET}/icon_128x128.png" >/dev/null 2>&1 || true
        sips -z 256 256   assets/icon.png --out "${ICONSET}/icon_128x128@2x.png" >/dev/null 2>&1 || true
        sips -z 256 256   assets/icon.png --out "${ICONSET}/icon_256x256.png" >/dev/null 2>&1 || true
        sips -z 512 512   assets/icon.png --out "${ICONSET}/icon_256x256@2x.png" >/dev/null 2>&1 || true
        sips -z 512 512   assets/icon.png --out "${ICONSET}/icon_512x512.png" >/dev/null 2>&1 || true
        sips -z 1024 1024 assets/icon.png --out "${ICONSET}/icon_512x512@2x.png" >/dev/null 2>&1 || true
        iconutil -c icns "${ICONSET}" -o "${RESOURCES}/AppIcon.icns" >/dev/null 2>&1 || true
    fi
    rm -rf "${ICONSET}"
fi

# 生成 Info.plist
cat > "${CONTENTS}/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>securevault</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>com.securevault.desktop</string>
    <key>CFBundleName</key>
    <string>${APP_NAME}</string>
    <key>CFBundleDisplayName</key>
    <string>${APP_NAME}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>${APP_VERSION}</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSSupportsAutomaticGraphicsSwitching</key>
    <true/>
</dict>
</plist>
EOF

# 移除整个 .app 包的隔离属性
xattr -cr "${BUNDLE}" 2>/dev/null || true

# 打包成免安装 ZIP 包
ZIP_NAME="${APP_NAME}-macOS-portable.zip"
rm -f "${ZIP_NAME}"
# 使用 ditto 打包以正确保留 macOS 扩展属性和权限
if command -v ditto >/dev/null 2>&1; then
    ditto -c -k --keepParent "${BUNDLE}" "${ZIP_NAME}"
else
    zip -q -r "${ZIP_NAME}" "${BUNDLE}"
fi

# 打包成 DMG 安装镜像（若环境支持 hdiutil）
DMG_NAME="${APP_NAME}.dmg"
if command -v hdiutil >/dev/null 2>&1; then
    echo "💿 正在生成 DMG 安装镜像..."
    DMG_STAGING="dmg_staging"
    rm -rf "${DMG_STAGING}" "${DMG_NAME}"
    mkdir -p "${DMG_STAGING}"
    cp -R "${BUNDLE}" "${DMG_STAGING}/"
    ln -s /Applications "${DMG_STAGING}/Applications"
    hdiutil create -volname "${APP_NAME}" -srcfolder "${DMG_STAGING}" -ov -format UDZO "${DMG_NAME}" >/dev/null 2>&1
    rm -rf "${DMG_STAGING}"
fi

echo "================================================================="
echo "✅ macOS 安装包构建成功！"
echo "   - App 目录: ${BUNDLE}"
if [ -f "${DMG_NAME}" ]; then
    echo "   - DMG 镜像: ${DMG_NAME} (拖拽安装)"
fi
echo "   - 绿色压缩包: ${ZIP_NAME} (解压即用)"
echo ""
echo "💡 macOS 用户使用说明："
echo "   1. 打开 ${DMG_NAME}，将 ${APP_NAME}.app 拖入 Applications 即可完成安装。"
echo "   2. 若首次打开出现『已损坏，无法打开』或『来自未识别的开发者』提示："
echo "      - 方法 A（命令行，推荐）：sudo xattr -rd com.apple.quarantine /Applications/${BUNDLE}"
echo "      - 方法 B（右键）：按住 Control 键或右键点击 SecureVault.app -> 选择【打开】-> 点击【仍要打开】"
echo "================================================================="
