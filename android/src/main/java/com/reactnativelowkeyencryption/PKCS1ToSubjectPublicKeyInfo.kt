import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*

class PKCS1ToSubjectPublicKeyInfo {
  private val BIT_STRING_TAG = 0x03
  private val SEQUENCE_TAG = 0x30
  private val NO_UNUSED_BITS = byteArrayOf(0x00)
  private val RSA_ALGORITHM_IDENTIFIER_SEQUENCE = byteArrayOf(0x30.toByte(), 0x0d.toByte(),
    0x06.toByte(), 0x09.toByte(), 0x2a.toByte(), 0x86.toByte(), 0x48.toByte(), 0x86.toByte(), 0xf7.toByte(), 0x0d.toByte(), 0x01.toByte(), 0x01.toByte(), 0x01.toByte(),
    0x05.toByte(), 0x00.toByte())

  @RequiresApi(Build.VERSION_CODES.O)
  @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
  fun decodePKCS1PublicKey(pkcs1PublicKeyEncoding: ByteArray?): RSAPublicKey {
    Log.d("IN ---->", Base64.getEncoder().encodeToString(pkcs1PublicKeyEncoding))
    val subjectPublicKeyInfo2 = createSubjectPublicKeyInfoEncoding(pkcs1PublicKeyEncoding)
    Log.d("OUT ---->", Base64.getEncoder().encodeToString(subjectPublicKeyInfo2))
    val rsaKeyFactory = KeyFactory.getInstance("RSA")
    return rsaKeyFactory.generatePublic(X509EncodedKeySpec(subjectPublicKeyInfo2)) as RSAPublicKey
  }

  @RequiresApi(Build.VERSION_CODES.O)
  fun decodePKCS1PrivateKey(pkcs1PrivateKeyEncoding: ByteArray?): RSAPrivateKey {
    Log.d("IN ---->", Base64.getEncoder().encodeToString(pkcs1PrivateKeyEncoding))
    val subjectPublicKeyInfo2 = createSubjectPublicKeyInfoEncoding(pkcs1PrivateKeyEncoding)
    Log.d("OUT ---->", Base64.getEncoder().encodeToString(subjectPublicKeyInfo2))
    val rsaKeyFactory = KeyFactory.getInstance("RSA")
    return rsaKeyFactory.generatePrivate(PKCS8EncodedKeySpec(subjectPublicKeyInfo2)) as RSAPrivateKey
  }

  private fun createSubjectPublicKeyInfoEncoding(pkcs1PublicKeyEncoding: ByteArray?): ByteArray {
    val subjectPublicKeyBitString = createDEREncoding(BIT_STRING_TAG, concat(NO_UNUSED_BITS, pkcs1PublicKeyEncoding!!))
    val subjectPublicKeyInfoValue = concat(RSA_ALGORITHM_IDENTIFIER_SEQUENCE, subjectPublicKeyBitString)
    return createDEREncoding(SEQUENCE_TAG, subjectPublicKeyInfoValue)
  }

  private fun concat(vararg bas: ByteArray): ByteArray {
    var len = 0
    for (i in bas.indices) {
      len += bas[i].size
    }
    val buf = ByteArray(len)
    var off = 0
    for (i in bas.indices) {
      System.arraycopy(bas[i], 0, buf, off, bas[i].size)
      off += bas[i].size
    }
    return buf
  }

  private fun createDEREncoding(tag: Int, value: ByteArray): ByteArray {
    require(!(tag < 0 || tag >= 0xFF)) { "Currently only single byte tags supported" }
    val lengthEncoding = createDERLengthEncoding(value.size)
    val size = 1 + lengthEncoding.size + value.size
    val derEncodingBuf = ByteArray(size)
    var off = 0
    derEncodingBuf[off++] = tag.toByte()
    System.arraycopy(lengthEncoding, 0, derEncodingBuf, off, lengthEncoding.size)
    off += lengthEncoding.size
    System.arraycopy(value, 0, derEncodingBuf, off, value.size)
    return derEncodingBuf
  }

  private fun createDERLengthEncoding(size: Int): ByteArray {
    if (size <= 0x7F) {
      // single byte length encoding
      return byteArrayOf(size.toByte())
    } else if (size <= 0xFF) {
      // double byte length encoding
      return byteArrayOf(0x81.toByte(), size.toByte())
    } else if (size <= 0xFFFF) {
      // triple byte length encoding
      return byteArrayOf(0x82.toByte(), (size shr java.lang.Byte.SIZE).toByte(), size.toByte())
    }
    throw IllegalArgumentException("size too large, only up to 64KiB length encoding supported: $size")
  }
}
