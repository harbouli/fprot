package com.fprot

import android.util.Base64
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object FprotCrypto {
  private val secureRandom = SecureRandom()
  private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
  private val L: BigInteger =
    BigInteger.ONE.shiftLeft(252).add(BigInteger("27742317777372353535851937790883648493"))
  private val A24: BigInteger = BigInteger.valueOf(121665)
  private val D: BigInteger =
    BigInteger.valueOf(-121665)
      .mod(P)
      .multiply(BigInteger.valueOf(121666).modInverse(P))
      .mod(P)
  private val D2: BigInteger = D.shiftLeft(1).mod(P)
  private val I_SQRT_M1: BigInteger =
    BigInteger.valueOf(2).modPow(P.subtract(BigInteger.ONE).shiftRight(2), P)

  private data class EdPoint(
    val x: BigInteger,
    val y: BigInteger,
    val z: BigInteger,
    val t: BigInteger,
  )

  private val ZERO_POINT = EdPoint(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO)
  private val BASE_POINT: EdPoint = run {
    val by = BigInteger.valueOf(4).multiply(BigInteger.valueOf(5).modInverse(P)).mod(P)
    val bx = recoverX(by, 0)!!
    EdPoint(bx, by, BigInteger.ONE, bx.multiply(by).mod(P))
  }
  private val U_BASE = ByteArray(32).apply { this[0] = 9 }

  fun toBase64Url(bytes: ByteArray): String =
    Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

  fun fromBase64Url(input: String): ByteArray = Base64.decode(input, Base64.URL_SAFE)

  fun randomBytes(size: Int): ByteArray {
    val out = ByteArray(size.coerceAtLeast(0))
    secureRandom.nextBytes(out)
    return out
  }

  fun sha256(data: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-256").digest(data)

  private fun sha512(vararg chunks: ByteArray): ByteArray {
    val md = MessageDigest.getInstance("SHA-512")
    for (chunk in chunks) {
      md.update(chunk)
    }
    return md.digest()
  }

  private fun fromLittleEndian(bytes: ByteArray): BigInteger {
    val rev = ByteArray(bytes.size + 1)
    for (i in bytes.indices) {
      rev[bytes.size - i] = bytes[i]
    }
    return BigInteger(rev)
  }

  private fun toLittleEndian32(value: BigInteger): ByteArray {
    val norm = value.mod(P.max(L))
    val raw = norm.toByteArray()
    val out = ByteArray(32)
    for (i in raw.indices) {
      val target = raw.size - 1 - i
      if (target in 0..31) {
        out[target] = raw[i]
      }
    }
    return out
  }

  // RFC 7748 X25519
  fun x25519(scalar32: ByteArray, u32: ByteArray): ByteArray {
    val kBytes = scalar32.copyOf(32)
    kBytes[0] = (kBytes[0].toInt() and 248).toByte()
    kBytes[31] = ((kBytes[31].toInt() and 127) or 64).toByte()
    val k = fromLittleEndian(kBytes)

    val uBytes = u32.copyOf(32)
    uBytes[31] = (uBytes[31].toInt() and 127).toByte()
    val x1 = fromLittleEndian(uBytes).mod(P)

    var x2 = BigInteger.ONE
    var z2 = BigInteger.ZERO
    var x3 = x1
    var z3 = BigInteger.ONE
    var swap = 0

    for (t in 254 downTo 0) {
      val kt = if (k.testBit(t)) 1 else 0
      swap = swap xor kt
      if (swap == 1) {
        val tx = x2; x2 = x3; x3 = tx
        val tz = z2; z2 = z3; z3 = tz
      }
      swap = kt

      val a = x2.add(z2).mod(P)
      val aa = a.multiply(a).mod(P)
      val b = x2.subtract(z2).add(P).mod(P)
      val bb = b.multiply(b).mod(P)
      val e = aa.subtract(bb).add(P).mod(P)
      val c = x3.add(z3).mod(P)
      val d = x3.subtract(z3).add(P).mod(P)
      val da = d.multiply(a).mod(P)
      val cb = c.multiply(b).mod(P)
      val sum = da.add(cb).mod(P)
      x3 = sum.multiply(sum).mod(P)
      val diff = da.subtract(cb).add(P).mod(P)
      z3 = x1.multiply(diff.multiply(diff).mod(P)).mod(P)
      x2 = aa.multiply(bb).mod(P)
      z2 = e.multiply(aa.add(A24.multiply(e).mod(P)).mod(P)).mod(P)
    }

    if (swap == 1) {
      val tx = x2; x2 = x3; x3 = tx
      val tz = z2; z2 = z3; z3 = tz
    }

    val res = x2.multiply(z2.modPow(P.subtract(BigInteger.valueOf(2)), P)).mod(P)
    return toLittleEndian32(res)
  }

  fun boxKeypair(): Pair<ByteArray, ByteArray> {
    val priv = randomBytes(32)
    priv[0] = (priv[0].toInt() and 248).toByte()
    priv[31] = ((priv[31].toInt() and 127) or 64).toByte()
    val pub = x25519(priv, U_BASE)
    return Pair(pub, priv)
  }

  private fun compareBytes(a: ByteArray, b: ByteArray): Int {
    val len = minOf(a.size, b.size)
    for (i in 0 until len) {
      val ua = a[i].toInt() and 0xff
      val ub = b[i].toInt() and 0xff
      if (ua != ub) return ua - ub
    }
    return a.size - b.size
  }

  fun deriveBoxKey(remotePub32: ByteArray, localPriv32: ByteArray): ByteArray {
    val localPub32 = x25519(localPriv32, U_BASE)
    require(!MessageDigest.isEqual(localPub32, remotePub32)) {
      "Peer public key matches local key"
    }
    val shared = x25519(localPriv32, remotePub32)
    require(!shared.all { it == 0.toByte() }) {
      "Invalid low-order X25519 public key"
    }
    val prefix = "fprot.box.v1".toByteArray(Charsets.UTF_8)
    val keys =
      if (compareBytes(localPub32, remotePub32) < 0) {
        localPub32 + remotePub32
      } else {
        remotePub32 + localPub32
      }
    return sha256(prefix + shared + keys)
  }

  fun aesGcmSeal(plaintext: ByteArray, nonce12: ByteArray, key32: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val spec = GCMParameterSpec(128, nonce12)
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key32, "AES"), spec)
    return cipher.doFinal(plaintext)
  }

  fun aesGcmOpen(ciphertextWithTag: ByteArray, nonce12: ByteArray, key32: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val spec = GCMParameterSpec(128, nonce12)
    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key32, "AES"), spec)
    return cipher.doFinal(ciphertextWithTag)
  }

  // RFC 8032 Ed25519
  private fun recoverX(y: BigInteger, sign: Int): BigInteger? {
    if (y >= P) return null
    val y2 = y.multiply(y).mod(P)
    val u = y2.subtract(BigInteger.ONE).add(P).mod(P)
    val v = D.multiply(y2).add(BigInteger.ONE).mod(P)
    val x2 = u.multiply(v.modInverse(P)).mod(P)
    if (x2 == BigInteger.ZERO) {
      return if (sign == 1) null else BigInteger.ZERO
    }
    var x = x2.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P)
    if (x.multiply(x).mod(P) != x2) {
      x = x.multiply(I_SQRT_M1).mod(P)
    }
    if (x.multiply(x).mod(P) != x2) {
      return null
    }
    if ((if (x.testBit(0)) 1 else 0) != sign) {
      x = P.subtract(x)
    }
    return x
  }

  private fun edAdd(p: EdPoint, q: EdPoint): EdPoint {
    val a = p.y.subtract(p.x).add(P).mod(P).multiply(q.y.subtract(q.x).add(P).mod(P)).mod(P)
    val b = p.y.add(p.x).mod(P).multiply(q.y.add(q.x).mod(P)).mod(P)
    val c = p.t.multiply(D2).mod(P).multiply(q.t).mod(P)
    val d = p.z.shiftLeft(1).mod(P).multiply(q.z).mod(P)
    val e = b.subtract(a).add(P).mod(P)
    val f = d.subtract(c).add(P).mod(P)
    val g = d.add(c).mod(P)
    val h = b.add(a).mod(P)
    return EdPoint(
      e.multiply(f).mod(P),
      g.multiply(h).mod(P),
      f.multiply(g).mod(P),
      e.multiply(h).mod(P),
    )
  }

  private fun edMul(point: EdPoint, scalar: BigInteger): EdPoint {
    var res = ZERO_POINT
    var cur = point
    var s = scalar
    while (s > BigInteger.ZERO) {
      if (s.testBit(0)) {
        res = edAdd(res, cur)
      }
      cur = edAdd(cur, cur)
      s = s.shiftRight(1)
    }
    return res
  }

  private fun encodePoint(p: EdPoint): ByteArray {
    val zInv = p.z.modInverse(P)
    val x = p.x.multiply(zInv).mod(P)
    val y = p.y.multiply(zInv).mod(P)
    val out = toLittleEndian32(y)
    if (x.testBit(0)) {
      out[31] = (out[31].toInt() or 0x80).toByte()
    }
    return out
  }

  private fun decodePoint(bytes: ByteArray): EdPoint? {
    if (bytes.size != 32) return null
    val copy = bytes.copyOf(32)
    val sign = (copy[31].toInt() ushr 7) and 1
    copy[31] = (copy[31].toInt() and 0x7f).toByte()
    val y = fromLittleEndian(copy)
    val x = recoverX(y, sign) ?: return null
    return EdPoint(x, y, BigInteger.ONE, x.multiply(y).mod(P))
  }

  fun signKeypair(): Pair<ByteArray, ByteArray> {
    val seed = randomBytes(32)
    val h = sha512(seed)
    val sBytes = h.copyOfRange(0, 32)
    sBytes[0] = (sBytes[0].toInt() and 248).toByte()
    sBytes[31] = ((sBytes[31].toInt() and 127) or 64).toByte()
    val s = fromLittleEndian(sBytes)
    val pub = encodePoint(edMul(BASE_POINT, s))
    val secret64 = seed + pub
    return Pair(pub, secret64)
  }

  fun signDetached(message: ByteArray, secretKey64: ByteArray): ByteArray {
    require(secretKey64.size == 64) { "Invalid Ed25519 secret key" }
    val seed = secretKey64.copyOfRange(0, 32)
    val pub = secretKey64.copyOfRange(32, 64)
    val h = sha512(seed)
    val sBytes = h.copyOfRange(0, 32)
    sBytes[0] = (sBytes[0].toInt() and 248).toByte()
    sBytes[31] = ((sBytes[31].toInt() and 127) or 64).toByte()
    val s = fromLittleEndian(sBytes)
    val prefix = h.copyOfRange(32, 64)

    val r = fromLittleEndian(sha512(prefix, message)).mod(L)
    val rEncoded = encodePoint(edMul(BASE_POINT, r))
    val k = fromLittleEndian(sha512(rEncoded, pub, message)).mod(L)
    val sScalar = r.add(k.multiply(s)).mod(L)
    return rEncoded + toLittleEndian32(sScalar)
  }

  fun verifyDetached(message: ByteArray, signature64: ByteArray, publicKey32: ByteArray): Boolean {
    if (signature64.size != 64 || publicKey32.size != 32) return false
    val rBytes = signature64.copyOfRange(0, 32)
    val sBytes = signature64.copyOfRange(32, 64)
    val sScalar = fromLittleEndian(sBytes)
    if (sScalar >= L) return false
    val rPoint = decodePoint(rBytes) ?: return false
    val aPoint = decodePoint(publicKey32) ?: return false
    val k = fromLittleEndian(sha512(rBytes, publicKey32, message)).mod(L)
    val lhs = encodePoint(edMul(BASE_POINT, sScalar))
    val rhs = encodePoint(edAdd(rPoint, edMul(aPoint, k)))
    return MessageDigest.isEqual(lhs, rhs)
  }
}
