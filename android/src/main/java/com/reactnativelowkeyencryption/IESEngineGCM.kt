package com.reactnativelowkeyencryption

import org.bouncycastle.crypto.*
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator
import org.bouncycastle.crypto.params.*
import org.bouncycastle.util.Arrays
import org.bouncycastle.util.BigIntegers
import java.io.ByteArrayInputStream
import java.io.IOException
import kotlin.experimental.xor


class IESEngineGCM {
  var agree: BasicAgreement
  var kdf: DerivationFunction
  var cipher: BufferedBlockCipher?
  var forEncryption = false
  var privParam: CipherParameters? = null
  var pubParam: CipherParameters? = null
  var param: IESParameters? = null
  lateinit var encodedPublicKey: ByteArray
  private var keyPairGenerator: EphemeralKeyPairGenerator? = null
  private var keyParser: KeyParser? = null
  private var IV: ByteArray? = null

  /**
   * set up for use with stream mode, where the key derivation function
   * is used to provide a stream of bytes to xor with the message.
   *
   * @param agree the key agreement used as the basis for the encryption
   * @param kdf   the key derivation function used for byte generation
   */
  constructor(
    agree: BasicAgreement,
    kdf: DerivationFunction) {
    this.agree = agree
    this.kdf = kdf
    cipher = null
  }

  /**
   * set up for use in conjunction with a block cipher to handle the
   * message.
   *
   * @param agree  the key agreement used as the basis for the encryption
   * @param kdf    the key derivation function used for byte generation
   * @param cipher the cipher to used for encrypting the message
   */
  constructor(
    agree: BasicAgreement,
    kdf: DerivationFunction,
    cipher: BufferedBlockCipher?) {
    this.agree = agree
    this.kdf = kdf
    this.cipher = cipher
  }

  /**
   * Initialise the encryptor.
   *
   * @param forEncryption whether or not this is encryption/decryption.
   * @param privParam     our private key parameters
   * @param pubParam      the recipient's/sender's public key parameters
   * @param params        encoding and derivation parameters, may be wrapped to include an IV for an underlying block cipher.
   */
  fun init(
    forEncryption: Boolean,
    privParam: CipherParameters?,
    pubParam: CipherParameters?,
    params: CipherParameters) {
    this.forEncryption = forEncryption
    this.privParam = privParam
    this.pubParam = pubParam
    encodedPublicKey = ByteArray(0)
    extractParams(params)
  }

  /**
   * Initialise the decryptor.
   *
   * @param publicKey      the recipient's/sender's public key parameters
   * @param params         encoding and derivation parameters, may be wrapped to include an IV for an underlying block cipher.
   * @param ephemeralKeyPairGenerator             the ephemeral key pair generator to use.
   */
  fun init(publicKey: AsymmetricKeyParameter?, params: CipherParameters, ephemeralKeyPairGenerator: EphemeralKeyPairGenerator?) {
    forEncryption = true
    pubParam = publicKey
    keyPairGenerator = ephemeralKeyPairGenerator
    extractParams(params)
  }

  /**
   * Initialise the encryptor.
   *
   * @param privateKey      the recipient's private key.
   * @param params          encoding and derivation parameters, may be wrapped to include an IV for an underlying block cipher.
   * @param publicKeyParser the parser for reading the ephemeral public key.
   */
  fun init(privateKey: AsymmetricKeyParameter?, params: CipherParameters, publicKeyParser: KeyParser?) {
    forEncryption = false
    privParam = privateKey
    keyParser = publicKeyParser
    extractParams(params)
  }

  private fun extractParams(params: CipherParameters) {
    if (params is ParametersWithIV) {
      IV = params.iv
      param = params.parameters as IESParameters
    } else {
      IV = null
      param = params as IESParameters
    }
  }

  @Throws(InvalidCipherTextException::class)
  private fun encryptBlock(
    `in`: ByteArray,
    inOff: Int,
    inLen: Int): ByteArray {
    var C: ByteArray? = null
    var K: ByteArray? = null
    var K1: ByteArray? = null
    var K2: ByteArray? = null
    var len: Int
    if (cipher == null) {
      // Streaming mode.
      K1 = ByteArray(inLen)
      K2 = ByteArray(param!!.macKeySize / 8)
      K = ByteArray(K1.size + K2.size)
      kdf.generateBytes(K, 0, K.size)
      if (encodedPublicKey.size != 0) {
        System.arraycopy(K, 0, K2, 0, K2.size)
        System.arraycopy(K, K2.size, K1, 0, K1.size)
      } else {
        System.arraycopy(K, 0, K1, 0, K1.size)
        System.arraycopy(K, inLen, K2, 0, K2.size)
      }
      C = ByteArray(inLen)
      for (i in 0 until inLen) {
        C[i] = (`in`[inOff + i] xor K1[i]) as Byte
      }
      len = inLen
    } else {
      // Block cipher mode.
      K1 = ByteArray((param as IESWithCipherParameters?)!!.cipherKeySize / 8)
      K2 = ByteArray(param!!.macKeySize / 8)
      K = ByteArray(K1.size + K2.size)
      kdf.generateBytes(K, 0, K.size)
      System.arraycopy(K, 0, K1, 0, K1.size)
      System.arraycopy(K, K1.size, K2, 0, K2.size)

      // If iv provided use it to initialise the cipher
      if (IV != null) {
        cipher!!.init(true, ParametersWithIV(KeyParameter(K1), IV))
      } else {
        cipher!!.init(true, ParametersWithIV(KeyParameter(K1), K2))
      }
      C = ByteArray(cipher!!.getOutputSize(inLen))
      len = cipher!!.processBytes(`in`, inOff, inLen, C, 0)
      len += cipher!!.doFinal(C, len)
    }


    // Output the triple (encodedPublicKey,C,T).
    val Output = ByteArray(encodedPublicKey.size + len)
    System.arraycopy(encodedPublicKey, 0, Output, 0, encodedPublicKey.size)
    System.arraycopy(C, 0, Output, encodedPublicKey.size, len)
    return Output
  }

  @Throws(InvalidCipherTextException::class)
  private fun decryptBlock(
    in_enc: ByteArray,
    inOff: Int,
    inLen: Int): ByteArray {
    var M: ByteArray? = null
    var K: ByteArray? = null
    var K1: ByteArray? = null
    var K2: ByteArray? = null
    var len: Int

    // Ensure that the length of the input is greater than the public key
    if (inLen < encodedPublicKey.size) {
      throw InvalidCipherTextException("Length of input must be greater than the MAC and encodedPublicKey combined")
    }
    if (cipher == null) {
      // Streaming mode.
      K1 = ByteArray(inLen - encodedPublicKey.size)
      K2 = ByteArray(param!!.macKeySize / 8)
      K = ByteArray(K1.size + K2.size)
      kdf.generateBytes(K, 0, K.size)
      if (encodedPublicKey.size != 0) {
        System.arraycopy(K, 0, K2, 0, K2.size)
        System.arraycopy(K, K2.size, K1, 0, K1.size)
      } else {
        System.arraycopy(K, 0, K1, 0, K1.size)
        System.arraycopy(K, K1.size, K2, 0, K2.size)
      }
      M = ByteArray(K1.size)
      for (i in K1.indices) {
        M[i] = (in_enc[inOff + encodedPublicKey.size + i] xor K1[i]) as Byte
      }
      len = K1.size
    } else {
      // Block cipher mode.
      K1 = ByteArray((param as IESWithCipherParameters?)!!.cipherKeySize / 8)
      K2 = ByteArray(param!!.macKeySize / 8)
      K = ByteArray(K1.size + K2.size)
      kdf.generateBytes(K, 0, K.size)
      System.arraycopy(K, 0, K1, 0, K1.size)
      System.arraycopy(K, K1.size, K2, 0, K2.size)

      // If IV provide use it to initialize the cipher
      if (IV != null) {
        cipher!!.init(false, ParametersWithIV(KeyParameter(K1), IV))
      } else {
        cipher!!.init(false, ParametersWithIV(KeyParameter(K1), K2))
      }
      M = ByteArray(cipher!!.getOutputSize(inLen - encodedPublicKey.size))
      len = cipher!!.processBytes(in_enc, inOff + encodedPublicKey.size, inLen - encodedPublicKey.size, M, 0)
      len += cipher!!.doFinal(M, len)
    }

    // Output the message.
    return Arrays.copyOfRange(M, 0, len)
  }

  @Throws(InvalidCipherTextException::class)
  fun processBlock(
    `in`: ByteArray,
    inOff: Int,
    inLen: Int): ByteArray {
    if (forEncryption) {
      if (keyPairGenerator != null) {
        val ephKeyPair = keyPairGenerator!!.generate()
        privParam = ephKeyPair.keyPair.private
        encodedPublicKey = ephKeyPair.encodedPublicKey
      }
    } else {
      if (keyParser != null) {
        val bIn = ByteArrayInputStream(`in`, inOff, inLen)
        try {
          pubParam = keyParser!!.readKey(bIn)
        } catch (e: IOException) {
          throw InvalidCipherTextException("unable to recover ephemeral public key: " + e.message, e)
        }
        val encLength = inLen - bIn.available()
        encodedPublicKey = Arrays.copyOfRange(`in`, inOff, inOff + encLength)
      }
    }

    // Compute the common value and convert to byte array.
    agree.init(privParam)
    val z = agree.calculateAgreement(pubParam)
    val sharedSecret = BigIntegers.asUnsignedByteArray(agree.fieldSize, z)
    return try {
      // Initialise the KDF.
      val kdfParam = KDFParameters(sharedSecret, encodedPublicKey)
      kdf.init(kdfParam)
      if (forEncryption) encryptBlock(`in`, inOff, inLen) else decryptBlock(`in`, inOff, inLen)
    } finally {
      Arrays.fill(sharedSecret, 0.toByte())
    }
  }

  @JvmName("getCipher1")
  fun getCipher(): BufferedBlockCipher? {
    return this.cipher
  }
}
