package com.reactnativelowkeyencryption

import android.os.Build
import androidx.annotation.RequiresApi
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.WritableMap
import java.util.*
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


@RequiresApi(Build.VERSION_CODES.O)
class SymmetricEncryption {
  private val algorithm = "AES"

  fun generateSymmetricKey(): WritableMap? {
    val keyGen = KeyGenerator.getInstance(algorithm)
    keyGen.init(256)

    val secretKey = keyGen.generateKey()
    val symmetricKey = Base64.getEncoder().encodeToString(secretKey.encoded)

    val key = Arguments.createMap()
    key.putString("symmetricKey", symmetricKey)
    return key
  }

  fun encryptStringWithSymmetricKey(key: String?, input: String?): String? {
    val decodedKey: ByteArray = Base64.getDecoder().decode(key)
    val symmetricKey: SecretKey = SecretKeySpec(decodedKey, 0, decodedKey.size, algorithm)

    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

    val initializationVector = byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    val iv = IvParameterSpec(initializationVector)

    cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, iv)

    val cipherText = cipher.doFinal(input?.toByteArray())
    return Base64.getEncoder()
      .encodeToString(cipherText)
  }

  fun decryptStringWithSymmetricKey(key: String?, cipherText: String?): String? {
    val decodedKey: ByteArray = Base64.getDecoder().decode(key)
    val symmetricKey: SecretKey = SecretKeySpec(decodedKey, 0, decodedKey.size, algorithm)

    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

    val initializationVector = byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    val iv = IvParameterSpec(initializationVector)

    cipher.init(Cipher.DECRYPT_MODE, symmetricKey, iv)

    val clearString = cipher.doFinal(Base64.getDecoder()
      .decode(cipherText))
    return String(clearString)
  }
}
