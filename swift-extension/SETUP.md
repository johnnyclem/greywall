# GreywallProxy macOS System Extension — Setup Guide

## Overview

This document covers the full setup process for building and running the GreywallProxy macOS system extension (`NETransparentProxyProvider`). It includes every problem encountered and how it was resolved.

## Prerequisites

- macOS with Xcode installed
- **Paid Apple Developer Program** ($99/year) — required for system extension entitlements. Free accounts cannot sign system extensions.
- XcodeGen (`brew install xcodegen`)

## Step 1: Apple Developer Account in Xcode

**Problem:** Xcode error "No Account for Team" — the build fails because Xcode doesn't have your Apple ID linked.

**Solution:** Open **Xcode → Settings → Accounts**, click **+**, add your Apple ID. This is a one-time GUI step — there is no CLI equivalent.

## Step 2: Correct Team ID

**Problem:** The `DEVELOPMENT_TEAM` in `project.yml` must be your actual Apple Team ID, not a certificate hash or personal identifier.

**How to find your Team ID:**
```bash
security find-certificate -a -c "Apple Development" -p \
  | openssl x509 -noout -subject
```
Look for the `OU=` field — that's your Team ID. The value in parentheses in the `CN=` field is a personal identifier, NOT the Team ID.

**Important:** If you have multiple teams (e.g., personal + organization), make sure you use the Team ID for the team with an active paid membership. Check which certificate belongs to which team:
```bash
security find-certificate -a -p \
  | openssl storeutl -noout -text -certs /dev/stdin 2>/dev/null \
  | grep -E "Subject:|OU="
```
Each certificate shows `OU=<TeamID>` and `O=<TeamName>`.

## Step 3: Register Your Mac as a Device

**Problem:** "Your team has no devices from which to generate a provisioning profile."

**Solution:**
1. Get your Mac's Provisioning UDID:
   ```bash
   system_profiler SPHardwareDataType | grep "Provisioning UDID"
   ```
2. Go to https://developer.apple.com/account/resources/devices/list
3. Select your team, click **+**, platform **macOS**, paste the UDID
4. Register

## Step 4: App Identifiers & Capabilities

On the Apple Developer portal (https://developer.apple.com/account/resources/identifiers/list), ensure two App IDs exist:

- `io.greywall.proxy` — with capabilities:
  - **System Extension**
  - **Network Extensions** (with "System Extension" type checked)
- `io.greywall.proxy.extension` — with capability:
  - **Network Extensions** (with "System Extension" type checked)

These may be auto-created by Xcode, but verify the capabilities are enabled.

## Step 5: Code Signing — "Mac Development" Certificate Issue

**Problem:** Xcode demands a "Mac Development" signing certificate, but only "Apple Development" exists. Apple no longer offers "Mac Development" as a certificate type.

**What does NOT work:**
- Setting `CODE_SIGN_IDENTITY: "Apple Development"` in project.yml — Xcode ignores it when `CODE_SIGN_STYLE: Automatic` and overrides to "Mac Development" for macOS targets.
- Setting `CODE_SIGN_STYLE: Manual` with `CODE_SIGN_IDENTITY: "Apple Development"` — when `DEVELOPMENT_TEAM` is set, Xcode still forces "Mac Development".

**Solution:** Use `CODE_SIGN_STYLE: Automatic` in `project.yml` and let Xcode manage signing. The "Mac Development" error goes away once the correct Team ID is used and the account is properly configured. Build with:
```bash
xcodebuild -project GreywallProxy.xcodeproj \
  -target GreywallProxy -configuration Debug \
  -allowProvisioningUpdates build
```

## Step 6: Entitlements Cleared by XcodeGen

**Problem:** Every time `xcodegen generate` runs, it overwrites the `.entitlements` files with empty `<dict/>`.

**Solution:** Always restore entitlements AFTER running xcodegen. The entitlements files are:

**`GreywallProxy/GreywallProxy.entitlements`:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.developer.system-extension.install</key>
    <true/>
    <key>com.apple.developer.networking.networkextension</key>
    <array>
        <string>app-proxy-provider</string>
    </array>
</dict>
</plist>
```

**`GreywallProxyExtension/GreywallProxyExtension.entitlements`:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.developer.networking.networkextension</key>
    <array>
        <string>app-proxy-provider</string>
    </array>
</dict>
</plist>
```

Additionally, xcodegen resets `ProvisioningStyle` and `CODE_SIGN_STYLE` to what's in `project.yml`. After running xcodegen, you must patch the `.pbxproj` to use `Automatic`:
```bash
# After xcodegen generate:
sed -i '' 's/ProvisioningStyle = Manual/ProvisioningStyle = Automatic/g' GreywallProxy.xcodeproj/project.pbxproj
sed -i '' 's/CODE_SIGN_STYLE = Manual/CODE_SIGN_STYLE = Automatic/g' GreywallProxy.xcodeproj/project.pbxproj
```

## Step 7: Provisioning Profile Entitlement Mismatch

**Problem:** Apple's auto-generated provisioning profiles contain `app-proxy-provider` but NOT `app-proxy-provider-systemextension`. Using the `-systemextension` suffix in entitlements causes a profile mismatch build error.

**Current status:** The entitlements use `app-proxy-provider` (without `-systemextension` suffix) to match what Apple provisions. This builds successfully. Whether this affects runtime behavior is still being validated (see Next Steps).

**Note:** Tailscale's production entitlements use `packet-tunnel-provider-systemextension` (with the suffix), which suggests they may have a custom provisioning profile. This might require requesting it from Apple at https://developer.apple.com/contact/request/network-extension/.

## Step 8: @main Not Triggering applicationDidFinishLaunching

**Problem:** Using `@main` attribute on `AppDelegate` for a `LSUIElement` app (no dock icon, no storyboard) resulted in the app process running but `applicationDidFinishLaunching` never being called. No logs appeared.

**Solution:** Replace `@main` with an explicit `main.swift`:
```swift
// GreywallProxy/main.swift
import Cocoa

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
```
Remove the `@main` attribute from `AppDelegate`.

## Step 9: App Must Be in /Applications

**Problem:** `sysextd` error: "App containing System Extension to be activated must be in /Applications folder."

**Solution:** Copy the built app to `/Applications` before running:
```bash
ditto build/Debug/GreywallProxy.app /Applications/GreywallProxy.app
open /Applications/GreywallProxy.app
```
Use `ditto` (not `cp -R`) to preserve extended attributes and code signatures.

## Step 10: handleNewFlow Returning false Drops Traffic

**Problem:** When the extension activated (before SIP fix was needed), returning `false` from `handleNewFlow()` dropped all network traffic instead of passing it through. WiFi appeared to disconnect.

**Solution:** For `NETransparentProxyProvider`, returning `false` means "drop the flow". To passthrough, you must return `true`, call `open()` on the flow, and pipe data through in both directions. See `TransparentProxyProvider.swift` for the implementation.

## Current Blocker: SIP System Extension Protection

**Problem:** `sysextd` logs: "no policy, cannot allow apps outside /Applications" — even when the app IS in `/Applications`. This is a macOS System Integrity Protection (SIP) restriction that blocks unsigned/non-notarized system extensions.

Production apps (like Tailscale, ProtonVPN) bypass this because they are **notarized** by Apple. For development, SIP's system extension restriction must be partially disabled.

### Development Setup (required once per machine)

1. **Restart into Recovery Mode:**
   - Apple Silicon: Hold Power button until "Loading startup options", click Options
   - Intel: Hold Cmd+R during boot

2. **Open Terminal** from the Utilities menu in Recovery Mode

3. **Disable system extension protection only:**
   ```bash
   csrutil enable --without sysexts
   ```
   This keeps SIP enabled for everything else (filesystem protection, etc.) but allows unsigned system extensions.

4. **Restart normally**

5. **Enable developer mode for system extensions:**
   ```bash
   systemextensionsctl developer on
   ```

6. Now the extension should activate and prompt for user approval in **System Settings → General → Login Items & Extensions → Network Extensions**.

### For Production / Distribution

The app must be:
- Signed with a Developer ID certificate (not just Apple Development)
- **Notarized** by Apple (`xcrun notarytool submit`)
- Distributed outside the App Store (system extensions are not allowed in the App Store)

## Quick Build & Run Reference

```bash
# 1. Generate Xcode project
xcodegen generate

# 2. Restore entitlements (xcodegen clears them)
# (restore GreywallProxy.entitlements and GreywallProxyExtension.entitlements)

# 3. Fix signing style (xcodegen sets Manual, we need Automatic)
sed -i '' 's/ProvisioningStyle = Manual/ProvisioningStyle = Automatic/g' GreywallProxy.xcodeproj/project.pbxproj
sed -i '' 's/CODE_SIGN_STYLE = Manual/CODE_SIGN_STYLE = Automatic/g' GreywallProxy.xcodeproj/project.pbxproj

# 4. Build
xcodebuild -project GreywallProxy.xcodeproj \
  -target GreywallProxy -configuration Debug \
  -allowProvisioningUpdates build

# 5. Deploy and run
killall GreywallProxy 2>/dev/null
rm -rf /Applications/GreywallProxy.app
ditto build/Debug/GreywallProxy.app /Applications/GreywallProxy.app
open /Applications/GreywallProxy.app

# 6. Watch logs
log stream --predicate 'subsystem BEGINSWITH "io.greywall"' --info

# 7. Debug log (file-based, always works)
cat /tmp/greywall_debug.log
```

## Debugging Tips

- **os.log / Logger** messages may not appear in `log stream` in some scenarios. The app includes a file-based debug logger that writes to `/tmp/greywall_debug.log` — always check this file first.
- **Log stream for both subsystems:**
  - App: `subsystem == "io.greywall.proxy.app"`
  - Extension: `subsystem == "io.greywall.proxy"`
- **sysextd logs** are essential for diagnosing extension activation issues:
  ```bash
  log show --predicate 'process == "sysextd"' --last 1m --debug --info
  ```
- **Check installed extensions:**
  ```bash
  systemextensionsctl list
  ```
- **Kill the app if network breaks:**
  ```bash
  killall GreywallProxy
  ```
