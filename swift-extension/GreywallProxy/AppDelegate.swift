import Cocoa
import SystemExtensions
import NetworkExtension
import os.log

private func debugLog(_ message: String) {
    let timestamp = ISO8601DateFormatter().string(from: Date())
    let line = "[\(timestamp)] \(message)\n"
    let path = "/tmp/greywall_debug.log"
    if let handle = FileHandle(forWritingAtPath: path) {
        handle.seekToEndOfFile()
        handle.write(line.data(using: .utf8)!)
        handle.closeFile()
    } else {
        FileManager.default.createFile(atPath: path, contents: line.data(using: .utf8))
    }
}

class AppDelegate: NSObject, NSApplicationDelegate, OSSystemExtensionRequestDelegate {

    private let log = Logger(subsystem: "io.greywall.proxy.app", category: "app")
    private let extensionBundleID = "io.greywall.proxy.extension"

    // MARK: - App lifecycle

    func applicationDidFinishLaunching(_ notification: Notification) {
        debugLog("applicationDidFinishLaunching called")
        log.info("GreywallProxy app launched")
        activateExtension()
    }

    // MARK: - System extension activation

    private func activateExtension() {
        debugLog("activateExtension: requesting activation of \(extensionBundleID)")
        log.info("Requesting activation of \(self.extensionBundleID)")
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionBundleID,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
        debugLog("activateExtension: request submitted")
    }

    // MARK: - OSSystemExtensionRequestDelegate

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        debugLog("didFinishWithResult: \(result.rawValue)")
        log.info("Extension activation finished: \(result.rawValue)")
        switch result {
        case .completed:
            log.info("Extension activated, configuring proxy manager")
            configureProxyManager()
        case .willCompleteAfterReboot:
            log.info("Extension will activate after reboot")
        @unknown default:
            log.warning("Unknown result: \(result.rawValue)")
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        debugLog("didFailWithError: \(error.localizedDescription)")
        log.error("Extension activation failed: \(error.localizedDescription)")
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        debugLog("requestNeedsUserApproval called")
        log.info("User approval needed -- check System Settings > Privacy & Security")
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        debugLog("actionForReplacingExtension: v\(existing.bundleShortVersion) -> v\(ext.bundleShortVersion)")
        log.info("Replacing existing extension v\(existing.bundleShortVersion) with v\(ext.bundleShortVersion)")
        return .replace
    }

    // MARK: - Proxy manager configuration

    private func configureProxyManager() {
        debugLog("configureProxyManager called")
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error {
                debugLog("loadAllFromPreferences error: \(error.localizedDescription)")
                self.log.error("Failed to load proxy managers: \(error.localizedDescription)")
                return
            }

            debugLog("loadAllFromPreferences: \(managers?.count ?? 0) managers found")
            let manager = managers?.first ?? NETransparentProxyManager()

            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = self.extensionBundleID
            proto.serverAddress = "127.0.0.1"

            manager.protocolConfiguration = proto
            manager.localizedDescription = "Greywall Proxy"
            manager.isEnabled = true

            manager.saveToPreferences { error in
                if let error {
                    debugLog("saveToPreferences error: \(error.localizedDescription)")
                    self.log.error("Failed to save proxy config: \(error.localizedDescription)")
                    return
                }
                debugLog("saveToPreferences success, starting tunnel")
                self.log.info("Proxy config saved, starting tunnel")
                manager.loadFromPreferences { error in
                    if let error {
                        debugLog("loadFromPreferences error: \(error.localizedDescription)")
                        self.log.error("Failed to reload: \(error.localizedDescription)")
                        return
                    }
                    do {
                        try manager.connection.startVPNTunnel()
                        debugLog("tunnel started successfully")
                        self.log.info("Tunnel started")
                    } catch {
                        debugLog("startVPNTunnel error: \(error.localizedDescription)")
                        self.log.error("Failed to start tunnel: \(error.localizedDescription)")
                    }
                }
            }
        }
    }
}
