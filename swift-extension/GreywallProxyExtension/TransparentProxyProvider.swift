import NetworkExtension
import os.log

class TransparentProxyProvider: NETransparentProxyProvider {

    private let log = Logger(subsystem: "io.greywall.proxy", category: "provider")

    // MARK: - Lifecycle

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        log.info("startProxy called")

        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        // Capture all outbound TCP
        let tcpRule = NENetworkRule(
            remoteNetwork: nil, remotePrefix: 0,
            localNetwork: nil, localPrefix: 0,
            protocol: .TCP, direction: .outbound
        )

        // Capture all outbound UDP (includes DNS on port 53)
        let udpRule = NENetworkRule(
            remoteNetwork: nil, remotePrefix: 0,
            localNetwork: nil, localPrefix: 0,
            protocol: .UDP, direction: .outbound
        )

        // Exclude loopback to avoid interfering with local services
        let loopbackV4 = NENetworkRule(
            remoteNetwork: NWHostEndpoint(hostname: "127.0.0.0", port: "0"),
            remotePrefix: 8,
            localNetwork: nil, localPrefix: 0,
            protocol: .any, direction: .any
        )
        let loopbackV6 = NENetworkRule(
            remoteNetwork: NWHostEndpoint(hostname: "::1", port: "0"),
            remotePrefix: 128,
            localNetwork: nil, localPrefix: 0,
            protocol: .any, direction: .any
        )

        settings.includedNetworkRules = [tcpRule, udpRule]
        settings.excludedNetworkRules = [loopbackV4, loopbackV6]

        setTunnelNetworkSettings(settings) { error in
            if let error {
                self.log.error("Failed to set network settings: \(error.localizedDescription)")
            } else {
                self.log.info("Network settings applied, proxy active")
            }
            completionHandler(error)
        }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.info("stopProxy called, reason: \(String(describing: reason))")
        completionHandler()
    }

    // MARK: - Flow handling (Step 1: passive logging with passthrough)

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        let meta = flow.metaData
        let signingID = meta.sourceAppSigningIdentifier
        let hostname = flow.remoteHostname ?? "<no hostname>"
        let pid = extractPID(from: meta.sourceAppAuditToken)

        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            let endpoint = tcpFlow.remoteEndpoint as? NWHostEndpoint
            let dest = endpoint.map { "\($0.hostname):\($0.port)" } ?? "<unknown>"
            log.info("TCP flow: pid=\(pid) app=\(signingID) host=\(hostname) dest=\(dest)")
            // Open the TCP flow and pipe data through transparently
            tcpFlow.open(withLocalEndpoint: nil) { error in
                if let error {
                    self.log.error("TCP open failed: \(error.localizedDescription)")
                    return
                }
                self.pipeTC(tcpFlow)
            }
        } else if let udpFlow = flow as? NEAppProxyUDPFlow {
            log.info("UDP flow: pid=\(pid) app=\(signingID) host=\(hostname)")
            // Open the UDP flow and pipe datagrams through transparently
            udpFlow.open(withLocalEndpoint: nil) { error in
                if let error {
                    self.log.error("UDP open failed: \(error.localizedDescription)")
                    return
                }
                self.pipeUDP(udpFlow)
            }
        }

        return true
    }

    // MARK: - TCP passthrough

    private func pipeTC(_ flow: NEAppProxyTCPFlow) {
        // Read from app, write to network (outbound)
        readTCPLoop(flow)
        // Read from network, write to app (inbound)
        writeTCPLoop(flow)
    }

    private func readTCPLoop(_ flow: NEAppProxyTCPFlow) {
        flow.readData { data, error in
            if let error {
                self.log.debug("TCP read done: \(error.localizedDescription)")
                flow.closeWriteWithError(error)
                return
            }
            guard let data, !data.isEmpty else {
                // EOF - close write direction
                flow.closeWriteWithError(nil)
                return
            }
            flow.write(data) { writeError in
                if let writeError {
                    self.log.debug("TCP write failed: \(writeError.localizedDescription)")
                    flow.closeWriteWithError(writeError)
                    return
                }
                // Continue reading
                self.readTCPLoop(flow)
            }
        }
    }

    private func writeTCPLoop(_ flow: NEAppProxyTCPFlow) {
        flow.readData { data, error in
            if let error {
                self.log.debug("TCP inbound read done: \(error.localizedDescription)")
                flow.closeReadWithError(error)
                return
            }
            guard let data, !data.isEmpty else {
                flow.closeReadWithError(nil)
                return
            }
            flow.write(data) { writeError in
                if let writeError {
                    self.log.debug("TCP inbound write failed: \(writeError.localizedDescription)")
                    flow.closeReadWithError(writeError)
                    return
                }
                self.writeTCPLoop(flow)
            }
        }
    }

    // MARK: - UDP passthrough

    private func pipeUDP(_ flow: NEAppProxyUDPFlow) {
        readUDPLoop(flow)
    }

    private func readUDPLoop(_ flow: NEAppProxyUDPFlow) {
        flow.readDatagrams { datagrams, endpoints, error in
            if let error {
                self.log.debug("UDP read done: \(error.localizedDescription)")
                flow.closeWriteWithError(error)
                return
            }
            guard let datagrams, let endpoints, !datagrams.isEmpty else {
                flow.closeWriteWithError(nil)
                return
            }
            flow.writeDatagrams(datagrams, sentBy: endpoints) { writeError in
                if let writeError {
                    self.log.debug("UDP write failed: \(writeError.localizedDescription)")
                    flow.closeWriteWithError(writeError)
                    return
                }
                self.readUDPLoop(flow)
            }
        }
    }

    // MARK: - Helpers

    private func extractPID(from auditToken: Data?) -> pid_t {
        guard let token = auditToken, token.count >= 24 else { return -1 }
        // audit_token_t is 8 x UInt32; PID is at index 5 (byte offset 20)
        return token.withUnsafeBytes { ptr in
            let tokens = ptr.bindMemory(to: UInt32.self)
            return pid_t(tokens[5])
        }
    }
}
