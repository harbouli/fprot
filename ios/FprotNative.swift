import CryptoKit
import Darwin
import Foundation
import React
import Security

@objc(FprotNative)
public class FprotNative: RCTEventEmitter {
  private let lock = NSLock()
  private let ioQueue = DispatchQueue(label: "com.fprot.tcp.io", attributes: .concurrent)
  private var servers: [Int: ServerEntry] = [:]
  private var sockets: [Int: SocketEntry] = [:]
  private var nextServerSocketId: Int = 1_000_000
  private var hasListeners = false

  private final class ServerEntry {
    let fd: Int32
    let source: DispatchSourceRead
    init(fd: Int32, source: DispatchSourceRead) {
      self.fd = fd
      self.source = source
    }
  }

  private final class SocketEntry {
    let fd: Int32
    let source: DispatchSourceRead
    let writeQueue: DispatchQueue
    var closed = false
    init(fd: Int32, source: DispatchSourceRead, id: Int) {
      self.fd = fd
      self.source = source
      self.writeQueue = DispatchQueue(label: "com.fprot.tcp.write.\(id)")
    }
  }

  public override static func requiresMainQueueSetup() -> Bool {
    return false
  }

  public override func supportedEvents() -> [String]! {
    return ["fprot_tcp_event"]
  }

  public override func startObserving() {
    hasListeners = true
  }

  public override func stopObserving() {
    hasListeners = false
  }

  private func emitTcpEvent(_ body: [String: Any]) {
    if hasListeners {
      sendEvent(withName: "fprot_tcp_event", body: body)
    }
  }

  // MARK: - Base64URL Helpers

  private static func toBase64Url(_ data: Data) -> String {
    return data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  private static func fromBase64Url(_ input: String) -> Data? {
    var base64 = input
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let rem = base64.count % 4
    if rem == 1 {
      return nil
    } else if rem == 2 {
      base64 += "=="
    } else if rem == 3 {
      base64 += "="
    }
    return Data(base64Encoded: base64)
  }

  private static func deriveBoxSymmetricKey(remotePubData: Data, localPrivData: Data) throws -> SymmetricKey {
    let privKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: localPrivData)
    let localPubData = privKey.publicKey.rawRepresentation
    if localPubData == remotePubData {
      throw NSError(domain: "FprotCrypto", code: 1, userInfo: [NSLocalizedDescriptionKey: "Peer public key matches local key"])
    }
    let pubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remotePubData)
    let sharedSecret = try privKey.sharedSecretFromKeyAgreement(with: pubKey)
    let sharedBytes = sharedSecret.withUnsafeBytes { Data($0) }
    if sharedBytes.allSatisfy({ $0 == 0 }) {
      throw NSError(domain: "FprotCrypto", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid low-order X25519 public key"])
    }
    var input = Data("fprot.box.v1".utf8)
    input.append(sharedBytes)
    if localPubData.lexicographicallyPrecedes(remotePubData) {
      input.append(localPubData)
      input.append(remotePubData)
    } else {
      input.append(remotePubData)
      input.append(localPubData)
    }
    let digest = SHA256.hash(data: input)
    return SymmetricKey(data: Data(digest))
  }

  // MARK: - Synchronous Crypto Methods

  @objc(randomBytes:)
  public func randomBytes(_ size: Double) -> NSString {
    let count = max(0, Int(size))
    var bytes = [UInt8](repeating: 0, count: count)
    _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    return Self.toBase64Url(Data(bytes)) as NSString
  }

  @objc(sha256:)
  public func sha256(_ utf8Input: String) -> NSString {
    let digest = SHA256.hash(data: Data(utf8Input.utf8))
    return Self.toBase64Url(Data(digest)) as NSString
  }

  @objc
  public func boxKeypair() -> NSString {
    let priv = Curve25519.KeyAgreement.PrivateKey()
    let pubB64 = Self.toBase64Url(priv.publicKey.rawRepresentation)
    let privB64 = Self.toBase64Url(priv.rawRepresentation)
    return "\(pubB64).\(privB64)" as NSString
  }

  @objc(boxSeal:nonceB64:remotePubB64:localPrivB64:)
  public func boxSeal(
    _ plaintextUtf8: String,
    nonceB64: String,
    remotePubB64: String,
    localPrivB64: String
  ) -> NSString {
    do {
      guard
        let nonceData = Self.fromBase64Url(nonceB64),
        let remotePubData = Self.fromBase64Url(remotePubB64),
        let localPrivData = Self.fromBase64Url(localPrivB64)
      else {
        return "ERR:Invalid Base64URL parameters"
      }
      let key = try Self.deriveBoxSymmetricKey(remotePubData: remotePubData, localPrivData: localPrivData)
      let nonce = try AES.GCM.Nonce(data: nonceData)
      let sealed = try AES.GCM.seal(Data(plaintextUtf8.utf8), using: key, nonce: nonce)
      var combined = Data(sealed.ciphertext)
      combined.append(sealed.tag)
      return ("OK:" + Self.toBase64Url(combined)) as NSString
    } catch {
      return ("ERR:" + error.localizedDescription) as NSString
    }
  }

  @objc(boxOpen:nonceB64:remotePubB64:localPrivB64:)
  public func boxOpen(
    _ ciphertextB64: String,
    nonceB64: String,
    remotePubB64: String,
    localPrivB64: String
  ) -> NSString {
    do {
      guard
        let combined = Self.fromBase64Url(ciphertextB64),
        combined.count >= 16,
        let nonceData = Self.fromBase64Url(nonceB64),
        let remotePubData = Self.fromBase64Url(remotePubB64),
        let localPrivData = Self.fromBase64Url(localPrivB64)
      else {
        return "ERR:Invalid encrypted frame"
      }
      let key = try Self.deriveBoxSymmetricKey(remotePubData: remotePubData, localPrivData: localPrivData)
      let nonce = try AES.GCM.Nonce(data: nonceData)
      let cipherLen = combined.count - 16
      let ciphertext = combined.prefix(cipherLen)
      let tag = combined.suffix(16)
      let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
      let plainData = try AES.GCM.open(box, using: key)
      guard let plainStr = String(data: plainData, encoding: .utf8) else {
        return "ERR:Invalid UTF-8 plaintext"
      }
      return ("OK:" + plainStr) as NSString
    } catch {
      return ("ERR:" + error.localizedDescription) as NSString
    }
  }

  @objc
  public func signKeypair() -> NSString {
    let priv = Curve25519.Signing.PrivateKey()
    let seed = priv.rawRepresentation
    let pub = priv.publicKey.rawRepresentation
    var secretKey64 = Data(seed)
    secretKey64.append(pub)
    return "\(Self.toBase64Url(pub)).\(Self.toBase64Url(secretKey64))" as NSString
  }

  @objc(signDetached:secretKey64B64:)
  public func signDetached(_ messageUtf8: String, secretKey64B64: String) -> NSString {
    do {
      guard let secretData = Self.fromBase64Url(secretKey64B64), secretData.count == 64 else {
        return "ERR:Invalid Ed25519 secret key"
      }
      let priv = try Curve25519.Signing.PrivateKey(rawRepresentation: secretData.prefix(32))
      let sig = try priv.signature(for: Data(messageUtf8.utf8))
      return ("OK:" + Self.toBase64Url(sig)) as NSString
    } catch {
      return ("ERR:" + error.localizedDescription) as NSString
    }
  }

  @objc(verifyDetached:signature64B64:publicKey32B64:)
  public func verifyDetached(
    _ messageUtf8: String,
    signature64B64: String,
    publicKey32B64: String
  ) -> NSNumber {
    do {
      guard
        let sigData = Self.fromBase64Url(signature64B64),
        sigData.count == 64,
        let pubData = Self.fromBase64Url(publicKey32B64),
        pubData.count == 32
      else {
        return NSNumber(value: false)
      }
      let pub = try Curve25519.Signing.PublicKey(rawRepresentation: pubData)
      let valid = pub.isValidSignature(sigData, for: Data(messageUtf8.utf8))
      return NSNumber(value: valid)
    } catch {
      return NSNumber(value: false)
    }
  }

  @objc(secretboxSeal:nonceB64:key32B64:)
  public func secretboxSeal(_ plaintextUtf8: String, nonceB64: String, key32B64: String) -> NSString {
    do {
      guard
        let nonceData = Self.fromBase64Url(nonceB64),
        let keyData = Self.fromBase64Url(key32B64),
        keyData.count == 32
      else {
        return "ERR:Invalid secretbox key or nonce"
      }
      let key = SymmetricKey(data: keyData)
      let nonce = try AES.GCM.Nonce(data: nonceData)
      let sealed = try AES.GCM.seal(Data(plaintextUtf8.utf8), using: key, nonce: nonce)
      var combined = Data(sealed.ciphertext)
      combined.append(sealed.tag)
      return ("OK:" + Self.toBase64Url(combined)) as NSString
    } catch {
      return ("ERR:" + error.localizedDescription) as NSString
    }
  }

  @objc(secretboxOpen:nonceB64:key32B64:)
  public func secretboxOpen(_ ciphertextB64: String, nonceB64: String, key32B64: String) -> NSString {
    do {
      guard
        let combined = Self.fromBase64Url(ciphertextB64),
        combined.count >= 16,
        let nonceData = Self.fromBase64Url(nonceB64),
        let keyData = Self.fromBase64Url(key32B64),
        keyData.count == 32
      else {
        return "ERR:Invalid secretbox ciphertext"
      }
      let key = SymmetricKey(data: keyData)
      let nonce = try AES.GCM.Nonce(data: nonceData)
      let cipherLen = combined.count - 16
      let box = try AES.GCM.SealedBox(
        nonce: nonce,
        ciphertext: combined.prefix(cipherLen),
        tag: combined.suffix(16)
      )
      let plainData = try AES.GCM.open(box, using: key)
      guard let plainStr = String(data: plainData, encoding: .utf8) else {
        return "ERR:Invalid UTF-8 plaintext"
      }
      return ("OK:" + plainStr) as NSString
    } catch {
      return ("ERR:" + error.localizedDescription) as NSString
    }
  }

  // MARK: - TCP Server & Client Methods

  private func configureSocketFlags(_ fd: Int32) {
    var one: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, socklen_t(MemoryLayout<Int32>.size))
  }

  private func attachSocketReadSource(socketId: Int, fd: Int32) {
    configureSocketFlags(fd)
    let flags = fcntl(fd, F_GETFL, 0)
    _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

    let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: ioQueue)
    let entry = SocketEntry(fd: fd, source: source, id: socketId)
    lock.lock()
    sockets[socketId] = entry
    lock.unlock()

    source.setEventHandler { [weak self] in
      guard let self = self else { return }
      var buffer = [UInt8](repeating: 0, count: 16384)
      while true {
        let bytesRead = Darwin.read(fd, &buffer, buffer.count)
        if bytesRead > 0 {
          let chunk = String(decoding: buffer[0..<bytesRead], as: UTF8.self)
          self.emitTcpEvent([
            "type": "data",
            "socketId": socketId,
            "data": chunk,
          ])
        } else if bytesRead == 0 {
          self.closeSocketInternal(socketId: socketId, emitClose: true)
          break
        } else {
          if errno == EAGAIN || errno == EWOULDBLOCK {
            break
          }
          let message = String(cString: strerror(errno))
          self.emitTcpEvent([
            "type": "error",
            "socketId": socketId,
            "error": message,
          ])
          self.closeSocketInternal(socketId: socketId, emitClose: true)
          break
        }
      }
    }

    source.setCancelHandler {
      Darwin.close(fd)
    }

    source.resume()
  }

  private func closeSocketInternal(socketId: Int, emitClose: Bool) {
    lock.lock()
    guard let entry = sockets.removeValue(forKey: socketId), !entry.closed else {
      lock.unlock()
      return
    }
    entry.closed = true
    lock.unlock()
    entry.source.cancel()
    if emitClose {
      emitTcpEvent([
        "type": "close",
        "socketId": socketId,
      ])
    }
  }

  @objc(tcpServerListen:host:port:resolve:reject:)
  public func tcpServerListen(
    _ serverId: Double,
    host: String,
    port: Double,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    let sid = Int(serverId)
    let fd = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    if fd < 0 {
      reject("TCP_SERVER_ERR", String(cString: strerror(errno)), nil)
      return
    }

    var one: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))

    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = in_port_t(UInt16(port)).bigEndian
    if host.isEmpty || host == "0.0.0.0" {
      addr.sin_addr.s_addr = INADDR_ANY.bigEndian
    } else if inet_pton(AF_INET, host, &addr.sin_addr) != 1 {
      Darwin.close(fd)
      reject("TCP_BIND_ERR", "Invalid IPv4 listen address: \(host)", nil)
      return
    }

    let bindResult = withUnsafePointer(to: &addr) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
      }
    }
    if bindResult != 0 {
      let msg = String(cString: strerror(errno))
      Darwin.close(fd)
      reject("TCP_BIND_ERR", msg, nil)
      return
    }

    if Darwin.listen(fd, 8) != 0 {
      let msg = String(cString: strerror(errno))
      Darwin.close(fd)
      reject("TCP_LISTEN_ERR", msg, nil)
      return
    }

    var boundAddr = sockaddr_in()
    var boundLen = socklen_t(MemoryLayout<sockaddr_in>.size)
    let nameResult = withUnsafeMutablePointer(to: &boundAddr) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        Darwin.getsockname(fd, $0, &boundLen)
      }
    }
    if nameResult != 0 {
      let msg = String(cString: strerror(errno))
      Darwin.close(fd)
      reject("TCP_SOCKNAME_ERR", msg, nil)
      return
    }
    let assignedPort = Int(UInt16(bigEndian: boundAddr.sin_port))

    let flags = fcntl(fd, F_GETFL, 0)
    _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

    let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: ioQueue)
    lock.lock()
    servers[sid] = ServerEntry(fd: fd, source: source)
    lock.unlock()

    source.setEventHandler { [weak self] in
      guard let self = self else { return }
      while true {
        var clientAddr = sockaddr_in()
        var clientLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let clientFd = withUnsafeMutablePointer(to: &clientAddr) {
          $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.accept(fd, $0, &clientLen)
          }
        }
        if clientFd < 0 {
          if errno == EAGAIN || errno == EWOULDBLOCK {
            break
          }
          break
        }
        self.lock.lock()
        let acceptedSocketId = self.nextServerSocketId
        self.nextServerSocketId += 1
        self.lock.unlock()

        self.emitTcpEvent([
          "type": "connection",
          "serverId": sid,
          "socketId": acceptedSocketId,
        ])
        self.attachSocketReadSource(socketId: acceptedSocketId, fd: clientFd)
      }
    }

    source.setCancelHandler {
      Darwin.close(fd)
    }

    source.resume()
    resolve(assignedPort)
  }

  @objc(tcpServerClose:resolve:reject:)
  public func tcpServerClose(
    _ serverId: Double,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    let sid = Int(serverId)
    lock.lock()
    let entry = servers.removeValue(forKey: sid)
    lock.unlock()
    entry?.source.cancel()
    resolve(nil)
  }

  @objc(tcpConnect:host:port:timeoutMs:resolve:reject:)
  public func tcpConnect(
    _ socketId: Double,
    host: String,
    port: Double,
    timeoutMs: Double,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    let sockId = Int(socketId)
    ioQueue.async { [weak self] in
      guard let self = self else { return }
      var hints = addrinfo()
      hints.ai_family = AF_INET
      hints.ai_socktype = SOCK_STREAM
      hints.ai_protocol = IPPROTO_TCP
      var res: UnsafeMutablePointer<addrinfo>?
      let portStr = String(Int(port))
      let gai = getaddrinfo(host, portStr, &hints, &res)
      if gai != 0 || res == nil {
        reject("TCP_CONNECT_ERR", "Unable to resolve host \(host)", nil)
        return
      }
      defer { freeaddrinfo(res) }

      let info = res!.pointee
      let fd = Darwin.socket(info.ai_family, info.ai_socktype, info.ai_protocol)
      if fd < 0 {
        reject("TCP_CONNECT_ERR", String(cString: strerror(errno)), nil)
        return
      }

      self.configureSocketFlags(fd)
      let flags = fcntl(fd, F_GETFL, 0)
      _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

      let connRes = Darwin.connect(fd, info.ai_addr, info.ai_addrlen)
      if connRes != 0 && errno != EINPROGRESS {
        let msg = String(cString: strerror(errno))
        Darwin.close(fd)
        reject("TCP_CONNECT_ERR", msg, nil)
        return
      }

      if connRes != 0 {
        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        let pollRes = Darwin.poll(&pfd, 1, Int32(max(1, Int(timeoutMs))))
        if pollRes <= 0 {
          Darwin.close(fd)
          reject("TCP_CONNECT_TIMEOUT", "Timed out connecting to \(host):\(Int(port))", nil)
          return
        }
        var soError: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len)
        if soError != 0 {
          let msg = String(cString: strerror(soError))
          Darwin.close(fd)
          reject("TCP_CONNECT_ERR", msg, nil)
          return
        }
      }

      self.attachSocketReadSource(socketId: sockId, fd: fd)
      resolve(nil)
    }
  }

  @objc(tcpWrite:data:resolve:reject:)
  public func tcpWrite(
    _ socketId: Double,
    data: String,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    let sockId = Int(socketId)
    lock.lock()
    guard let entry = sockets[sockId], !entry.closed else {
      lock.unlock()
      reject("TCP_WRITE_ERR", "Socket is not connected", nil)
      return
    }
    lock.unlock()

    let utf8 = Array(data.utf8)
    entry.writeQueue.async {
      var offset = 0
      while offset < utf8.count {
        let written = utf8.withUnsafeBufferPointer { ptr -> Int in
          return Darwin.write(entry.fd, ptr.baseAddress! + offset, utf8.count - offset)
        }
        if written > 0 {
          offset += written
        } else if written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
          var pfd = pollfd(fd: entry.fd, events: Int16(POLLOUT), revents: 0)
          _ = Darwin.poll(&pfd, 1, 1000)
        } else {
          let msg = String(cString: strerror(errno))
          reject("TCP_WRITE_ERR", msg, nil)
          return
        }
      }
      resolve(nil)
    }
  }

  @objc(tcpDestroy:resolve:reject:)
  public func tcpDestroy(
    _ socketId: Double,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    closeSocketInternal(socketId: Int(socketId), emitClose: true)
    resolve(nil)
  }
}
