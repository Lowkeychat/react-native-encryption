package com.reactnativelowkeyencryption

import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableMap
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.KDF2BytesGenerator
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.IESParameterSpec
import org.bouncycastle.math.ec.ECPoint
import java.security.*
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*
import javax.crypto.Cipher


@RequiresApi(Build.VERSION_CODES.O)
class AsymmetricECCEncryption {
  fun generateKeyPair(): WritableMap {
    // Add BouncyCastle
    Security.removeProvider("BC")
    Security.addProvider(BouncyCastleProvider())
    val keyPairGenerator = KeyPairGenerator.getInstance("ECDH")
    keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"))
    val keyPair = keyPairGenerator.generateKeyPair()
    //val kpg = KeyPairGenerator.getInstance(algorithm)
    // kpg.initialize(256)
    // val keyPair = kpg.genKeyPair()

    val publicKey = keyPair.public.encoded;
    val privateKey = keyPair.private.encoded;
    val ecKey = Arrays.copyOfRange(publicKey, 26, publicKey.size);

    Log.d("ecKey size", ecKey.size.toString())

    val publicKeyBase64 =  Base64.getEncoder().encodeToString(ecKey)
    val privateKeyBase64 =  Base64.getEncoder().encodeToString(privateKey)


    val keys = Arguments.createMap()
    keys.putString("publicKey", publicKeyBase64)
    keys.putString("privateKey", privateKeyBase64)

    return keys
  }

  fun ByteArray.toHex(): String = joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }

  fun encryptGroup(publicKeysBase64: ArrayList<String>, inputString: String?): WritableMap? {
    Security.removeProvider("BC")
    Security.addProvider(BouncyCastleProvider())

    val list = Arguments.createMap()
    val decoder = Base64.getDecoder()

    val cipher = IESCipherGCM(
      IESEngineGCM(
        ECDHBasicAgreement(),
        KDF2BytesGenerator(SHA256Digest()),
        AESGCMBlockCipher()), 16)

    for(publicKeyBase64 in publicKeysBase64) {
      val publicKeyByteArray: ByteArray = decoder.decode(publicKeyBase64)

      val kf = KeyFactory.getInstance("ECDH")
      val ecSpec: ECNamedCurveParameterSpec? = ECNamedCurveTable.getParameterSpec("secp256r1")
      val point: ECPoint? = ecSpec?.getCurve()?.decodePoint(publicKeyByteArray)
      val pubSpec = org.bouncycastle.jce.spec.ECPublicKeySpec(point, ecSpec)
      val publicKey = kf.generatePublic(pubSpec) as ECPublicKey

      val params = IESParameterSpec(null, null, 128, 128, null)
      cipher.engineInit(Cipher.ENCRYPT_MODE, publicKey, params, SecureRandom())

      val inputData = inputString?.toByteArray() as ByteArray
      val chiperData = cipher.engineDoFinal(inputData, 0, inputData.size)

      val md = MessageDigest.getInstance("SHA1")
      md.update(publicKeyByteArray)
      val fingerprint = md.digest().toHex()

      list.putString(fingerprint, Base64.getEncoder().encodeToString(chiperData))
    }
    return list;
  }

  fun decryptGroup(publicKeyBase64: String, privateKeyBase64: String, messages: ReadableMap): String {
    Security.removeProvider("BC")
    Security.addProvider(BouncyCastleProvider())

    var privateKeyBaseString64: String = privateKeyBase64;
    val decoder = Base64.getDecoder()

    val publicKeyByteArray: ByteArray = decoder.decode(publicKeyBase64)
    val md = MessageDigest.getInstance("SHA1")
    md.update(publicKeyByteArray)
    val fingerprint = md.digest().toHex()

    val inputString = messages.getString(fingerprint)

    val privateKeyByteArray: ByteArray = decoder.decode(privateKeyBaseString64)

    val keySpec = PKCS8EncodedKeySpec(privateKeyByteArray)
    val keyFactory = KeyFactory.getInstance("ECDH")
    val privateKey = keyFactory.generatePrivate(keySpec) as ECPrivateKey

    val inputStringByteArray: ByteArray = decoder.decode(inputString) as ByteArray

    val cipher = IESCipherGCM(
      IESEngineGCM(
        ECDHBasicAgreement(),
        KDF2BytesGenerator(SHA256Digest()),
        AESGCMBlockCipher()), 16)
    val params = IESParameterSpec(null, null, 128, 128, null)
    cipher.engineInit(Cipher.DECRYPT_MODE, privateKey, params, SecureRandom())

    val decryptedByteArray = cipher.engineDoFinal(inputStringByteArray, 0, inputStringByteArray.size)

    return String(decryptedByteArray, Charsets.UTF_8);
  }
}

