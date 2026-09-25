package com.fprot

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.modules.core.DeviceEventManagerModule
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class FprotNativeModule(private val reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {

  private val executor = Executors.newCachedThreadPool()
  private val servers = ConcurrentHashMap<Int, ServerSocket>()
  private val sockets = ConcurrentHashMap<Int, SocketEntry>()
  private val nextServerSocketId = AtomicInteger(1_000_000)

  private class SocketEntry(
    val socket: Socket,
    val output: OutputStream,
  ) {
    val closed = AtomicBoolean(false)
    val writeLock = Any()
  }

  override fun getName(): String = "FprotNative"

  @ReactMethod
  fun addListener(eventName: String) {
    // Required for RN NativeEventEmitter
  }

  @ReactMethod
  fun removeListeners(count: Double) {
    // Required for RN NativeEventEmitter
  }

  private fun emitTcpEvent(
    type: String,
    socketId: Int,
    serverId: Int? = null,
    data: String? = null,
    error: String? = null,
  ) {
    if (!reactContext.hasActiveReactInstance()) return
    val map = Arguments.createMap()
    map.putString("type", type)
    map.putInt("socketId", socketId)
    if (serverId != null) map.putInt("serverId", serverId)
    if (data != null) map.putString("data", data)
    if (error != null) map.putString("error", error)
    reactContext
      .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
      .emit("fprot_tcp_event", map)
  }

  // MARK: - Synchronous Crypto Methods

  @ReactMethod(isBlockingSynchronousMethod = true)
  fun randomBytes(size: Double): String =
    FprotCrypto.toBase64Url(FprotCrypto.randomBytes(size.toInt()))

  @ReactMethod(isBlockingSynchronousMethod = true)
  fun sha256(utf8Input: String): String =
    FprotCrypto.toBase64Url(FprotCrypto.sha256(utf8Input.toByteArray(Charsets.UTF_8)))

  @ReactMethod(isBlockingSynchronousMethod = true)
  fun boxKeypair(): String {
    val (pub, priv) = FprotCrypto.boxKeypair()
    return "${FprotCrypto.toBase64Url(pub)}.${FprotCrypto.toBase64Url(priv)}"
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  fun boxSeal(
    plaintextUtf8: String,
    nonceB64: String,
    remotePubB64: String,
    localPrivB64: String,
  ): String {
    return try {
      val nonce = FprotCrypto.fromBase64Url(nonceB64)
      val remotePub = FprotCrypto.fromBase64Url(remotePubB64)
      val localPriv = FprotCrypto.fromBase64Url(localPrivB64)
      val key = FprotCrypto.deriveBoxKey(remotePub, localPriv)
      val sealed = FprotCrypto.aesGcmSeal(plaintextUtf8.toByteArray(Charsets.UTF_8), nonce, key)
      "OK:${FprotCrypto.toBase64Url(sealed)}"
    } catch (e: Throwable) {
      "ERR:${e.message ?: "Encryption failed"}"
    }
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  fun boxOpen(
    ciphertextB64: String,
    nonceB64: String,
    remotePubB64: String,
    localPrivB64: String,
  ): String {
    return try {
      val ciphertext = FprotCrypto.fromBase64Url(ciphertextB64)
      val nonce = FprotCrypto.fromBase64Url(nonceB64)
      val remotePub = FprotCrypto.fromBase64Url(remotePubB64)
      val localPriv = FprotCrypto.fromBase64Url(localPrivB64)
      val key = FprotCrypto.deriveBoxKey(remotePub, localPriv)
      val plain = FprotCrypto.aesGcmOpen(ciphertext, nonce, key)
      "OK:${String(plain, Charsets.UTF_8)}"
    } catch (e: Throwable) {
      "ERR:${e.message ?: "Decryption failed"}"
    }
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  fun signKeypair(): String {
    val (pub, secret64) = FprotCrypto.signKeypair()
    return "${FprotCrypto.toBase64Url(pub)}.${FprotCrypto.toBase64Url(secret64)}"
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  fun signDetached(messageUtf8: String, secretKey64B64: String): String {
    return try {
      val secret64 = FprotCrypto.fromBase64Url(secretKey64B64)
      val sig = FprotCrypto.signDetached(messageUtf8.toByteArray(Charsets.UTF_8), secret64)
      "OK:${FprotCrypto.toBase64Url(sig)}"
    } catch (e: Throwable) {
      "ERR:${e.message ?: "Sign failed"}"
    }
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  fun verifyDetached(
    messageUtf8: String,
    signature64B64: String,
    publicKey32B64: String,
  ): Boolean {
    return try {
      val sig = FprotCrypto.fromBase64Url(signature64B64)
      val pub = FprotCrypto.fromBase64Url(publicKey32B64)
      FprotCrypto.verifyDetached(messageUtf8.toByteArray(Charsets.UTF_8), sig, pub)
    } catch (_: Throwable) {
      false
    }
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  fun secretboxSeal(plaintextUtf8: String, nonceB64: String, key32B64: String): String {
    return try {
      val nonce = FprotCrypto.fromBase64Url(nonceB64)
      val key = FprotCrypto.fromBase64Url(key32B64)
      val sealed = FprotCrypto.aesGcmSeal(plaintextUtf8.toByteArray(Charsets.UTF_8), nonce, key)
      "OK:${FprotCrypto.toBase64Url(sealed)}"
    } catch (e: Throwable) {
      "ERR:${e.message ?: "Secretbox seal failed"}"
    }
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  fun secretboxOpen(ciphertextB64: String, nonceB64: String, key32B64: String): String {
    return try {
      val ciphertext = FprotCrypto.fromBase64Url(ciphertextB64)
      val nonce = FprotCrypto.fromBase64Url(nonceB64)
      val key = FprotCrypto.fromBase64Url(key32B64)
      val plain = FprotCrypto.aesGcmOpen(ciphertext, nonce, key)
      "OK:${String(plain, Charsets.UTF_8)}"
    } catch (e: Throwable) {
      "ERR:${e.message ?: "Secretbox open failed"}"
    }
  }

  // MARK: - TCP Server & Client Methods

  private fun startSocketReader(socketId: Int, socket: Socket) {
    socket.tcpNoDelay = true
    socket.keepAlive = true
    val entry = SocketEntry(socket, socket.getOutputStream())
    sockets[socketId] = entry

    executor.execute {
      val buf = ByteArray(16384)
      val input: InputStream = socket.getInputStream()
      try {
        while (!entry.closed.get()) {
          val read = input.read(buf)
          if (read > 0) {
            val chunk = String(buf, 0, read, Charsets.UTF_8)
            emitTcpEvent(type = "data", socketId = socketId, data = chunk)
          } else {
            break
          }
        }
      } catch (e: Throwable) {
        if (!entry.closed.get()) {
          emitTcpEvent(
            type = "error",
            socketId = socketId,
            error = e.message ?: "Socket read error",
          )
        }
      } finally {
        closeSocketInternal(socketId, emitClose = true)
      }
    }
  }

  private fun closeSocketInternal(socketId: Int, emitClose: Boolean) {
    val entry = sockets.remove(socketId) ?: return
    if (!entry.closed.compareAndSet(false, true)) return
    try {
      entry.socket.close()
    } catch (_: Throwable) {
    }
    if (emitClose) {
      emitTcpEvent(type = "close", socketId = socketId)
    }
  }

  @ReactMethod
  fun tcpServerListen(serverId: Double, host: String, port: Double, promise: Promise) {
    val sid = serverId.toInt()
    executor.execute {
      try {
        val server = ServerSocket()
        server.reuseAddress = true
        val bindAddr =
          if (host.isEmpty() || host == "0.0.0.0") {
            InetSocketAddress(port.toInt())
          } else {
            InetSocketAddress(InetAddress.getByName(host), port.toInt())
          }
        server.bind(bindAddr, 8)
        servers[sid] = server
        promise.resolve(server.localPort)

        while (!server.isClosed) {
          try {
            val client = server.accept()
            val acceptedId = nextServerSocketId.getAndIncrement()
            emitTcpEvent(type = "connection", socketId = acceptedId, serverId = sid)
            startSocketReader(acceptedId, client)
          } catch (_: Throwable) {
            break
          }
        }
      } catch (e: Throwable) {
        promise.reject("TCP_LISTEN_ERR", e.message ?: "Failed to listen", e)
      }
    }
  }

  @ReactMethod
  fun tcpServerClose(serverId: Double, promise: Promise) {
    val server = servers.remove(serverId.toInt())
    try {
      server?.close()
    } catch (_: Throwable) {
    }
    promise.resolve(null)
  }

  @ReactMethod
  fun tcpConnect(socketId: Double, host: String, port: Double, timeoutMs: Double, promise: Promise) {
    val sockId = socketId.toInt()
    executor.execute {
      val socket = Socket()
      try {
        socket.tcpNoDelay = true
        socket.keepAlive = true
        socket.connect(
          InetSocketAddress(host, port.toInt()),
          timeoutMs.toInt().coerceAtLeast(1),
        )
        startSocketReader(sockId, socket)
        promise.resolve(null)
      } catch (e: Throwable) {
        try {
          socket.close()
        } catch (_: Throwable) {
        }
        promise.reject("TCP_CONNECT_ERR", e.message ?: "Failed to connect", e)
      }
    }
  }

  @ReactMethod
  fun tcpWrite(socketId: Double, data: String, promise: Promise) {
    val entry = sockets[socketId.toInt()]
    if (entry == null || entry.closed.get()) {
      promise.reject("TCP_WRITE_ERR", "Socket is not connected")
      return
    }
    val bytes = data.toByteArray(Charsets.UTF_8)
    executor.execute {
      try {
        synchronized(entry.writeLock) {
          entry.output.write(bytes)
          entry.output.flush()
        }
        promise.resolve(null)
      } catch (e: Throwable) {
        promise.reject("TCP_WRITE_ERR", e.message ?: "Write failed", e)
      }
    }
  }

  @ReactMethod
  fun tcpDestroy(socketId: Double, promise: Promise) {
    closeSocketInternal(socketId.toInt(), emitClose = true)
    promise.resolve(null)
  }
}
