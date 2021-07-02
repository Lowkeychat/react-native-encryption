package com.reactnativelowkeyencryption

import org.bouncycastle.crypto.BlockCipher
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.engines.DESedeEngine
import org.bouncycastle.crypto.engines.IESEngine
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator
import org.bouncycastle.crypto.generators.KDF2BytesGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.*
import org.bouncycastle.crypto.parsers.ECIESPublicKeyParser
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
import org.bouncycastle.jcajce.provider.asymmetric.util.IESUtil
import org.bouncycastle.jcajce.util.BCJcaJceHelper
import org.bouncycastle.jcajce.util.JcaJceHelper
import org.bouncycastle.jce.interfaces.ECKey
import org.bouncycastle.jce.interfaces.IESKey
import org.bouncycastle.jce.spec.IESParameterSpec
import org.bouncycastle.util.Strings
import java.io.ByteArrayOutputStream
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.*

class IESCipherGCM : CipherSpi {
  private val helper: JcaJceHelper = BCJcaJceHelper()
  private var ivLength: Int
  private var engine: IESEngineGCM
  private var state = -1
  private val buffer = ByteArrayOutputStream()
  lateinit var engineParam: AlgorithmParameters
  private var engineSpec: IESParameterSpec? = null
  private var key: AsymmetricKeyParameter? = null
  private var random: SecureRandom? = null
  private var dhaesMode = false
  private var otherKeyParameter: AsymmetricKeyParameter? = null

  constructor(engine: IESEngineGCM) {
    this.engine = engine
    ivLength = 0
  }

  constructor(engine: IESEngineGCM, ivLength: Int) {
    this.engine = engine
    this.ivLength = ivLength
  }

  public override fun engineGetBlockSize(): Int {
    return if (engine.getCipher() != null) {
      engine.getCipher()!!.getBlockSize()
    } else {
      0
    }
  }

  public override fun engineGetKeySize(key: Key): Int {
    return if (key is ECKey) {
      (key as ECKey).parameters.curve.fieldSize
    } else {
      throw IllegalArgumentException("not an EC key")
    }
  }

  public override fun engineGetIV(): ByteArray? {
    return null
  }

  public override fun engineGetParameters(): AlgorithmParameters {
    if (engineParam == null && engineSpec != null) {
      try {
        engineParam = helper.createAlgorithmParameters("IES")
        engineParam.init(engineSpec)
      } catch (e: Exception) {
        throw RuntimeException(e.toString())
      }
    }
    return engineParam!!
  }

  @Throws(NoSuchAlgorithmException::class)
  public override fun engineSetMode(mode: String) {
    val modeName = Strings.toUpperCase(mode)
    dhaesMode = if (modeName == "NONE") {
      false
    } else if (modeName == "DHAES") {
      true
    } else {
      throw IllegalArgumentException("can't support mode $mode")
    }
  }

  public override fun engineGetOutputSize(inputLen: Int): Int {
    val len1: Int
    val len2: Int
    val len3: Int
    checkNotNull(key) { "cipher not initialised" }
    len1 = 0
    len2 = if (otherKeyParameter == null) {
      1 + 2 * ((key as ECKeyParameters).parameters.curve.fieldSize + 7) / 8
    } else {
      0
    }
    len3 = if (engine.getCipher() == null) {
      inputLen
    } else if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE) {
      engine.getCipher()!!.getOutputSize(inputLen)
    } else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE) {
      engine.getCipher()!!.getOutputSize(inputLen - len1 - len2)
    } else {
      throw IllegalStateException("cipher not initialised")
    }
    return if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE) {
      buffer.size() + len1 + len2 + len3
    } else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE) {
      buffer.size() - len1 - len2 + len3
    } else {
      throw IllegalStateException("cipher not initialised")
    }
  }

  @Throws(NoSuchPaddingException::class)
  public override fun engineSetPadding(padding: String) {
    val paddingName = Strings.toUpperCase(padding)

    // TDOD: make this meaningful...
    if (paddingName == "NOPADDING") {
    } else if (paddingName == "PKCS5PADDING" || paddingName == "PKCS7PADDING") {
    } else {
      throw NoSuchPaddingException("padding not available with IESCipher")
    }
  }

  // Initialisation methods
  @Throws(InvalidKeyException::class, InvalidAlgorithmParameterException::class)
  public override fun engineInit(
    opmode: Int,
    key: Key,
    params: AlgorithmParameters,
    random: SecureRandom) {
    var paramSpec: AlgorithmParameterSpec? = null
    if (params != null) {
      paramSpec = try {
        params.getParameterSpec(IESParameterSpec::class.java)
      } catch (e: Exception) {
        throw InvalidAlgorithmParameterException("cannot recognise parameters: $e")
      }
    }
    engineParam = params
    engineInit(opmode, key, paramSpec!!, random)
  }

  @Throws(InvalidAlgorithmParameterException::class, InvalidKeyException::class)
  public override fun engineInit(
    opmode: Int,
    key: Key,
    engineSpec: AlgorithmParameterSpec,
    random: SecureRandom) {
    otherKeyParameter = null

    // Use default parameters (including cipher key size) if none are specified
    if (engineSpec == null) {
      var nonce: ByteArray? = null
      if (ivLength != 0 && opmode == Cipher.ENCRYPT_MODE) {
        nonce = ByteArray(ivLength)
        random.nextBytes(nonce)
      }
      this.engineSpec = IESUtil.guessParameterSpec(engine.getCipher(), nonce)
    } else if (engineSpec is IESParameterSpec) {
      this.engineSpec = engineSpec
    } else {
      throw InvalidAlgorithmParameterException("must be passed IES parameters")
    }
    val nonce = this.engineSpec!!.nonce
    if (nonce != null) {
      if (ivLength == 0) {
        throw InvalidAlgorithmParameterException("NONCE present in IES Parameters when none required")
      } else if (nonce.size != ivLength) {
        throw InvalidAlgorithmParameterException("NONCE in IES Parameters needs to be $ivLength bytes long")
      }
    }

    // Parse the recipient's key
    if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
      if (key is PublicKey) {
        this.key = ECUtil.generatePublicKeyParameter(key)
      } else if (key is IESKey) {
        val ieKey = key
        this.key = ECUtil.generatePublicKeyParameter(ieKey.public)
        otherKeyParameter = ECUtil.generatePrivateKeyParameter(ieKey.private)
      } else {
        throw InvalidKeyException("must be passed recipient's public EC key for encryption")
      }
    } else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE) {
      if (key is PrivateKey) {
        this.key = ECUtil.generatePrivateKeyParameter(key)
      } else if (key is IESKey) {
        val ieKey = key
        otherKeyParameter = ECUtil.generatePublicKeyParameter(ieKey.public)
        this.key = ECUtil.generatePrivateKeyParameter(ieKey.private)
      } else {
        throw InvalidKeyException("must be passed recipient's private EC key for decryption")
      }
    } else {
      throw InvalidKeyException("must be passed EC key")
    }
    this.random = random
    state = opmode
    buffer.reset()
  }

  @Throws(InvalidKeyException::class)
  public override fun engineInit(
    opmode: Int,
    key: Key,
    random: SecureRandom) {
    try {
      engineInit(opmode, key, (null as AlgorithmParameterSpec?)!!, random)
    } catch (e: InvalidAlgorithmParameterException) {
      throw IllegalArgumentException("can't handle supplied parameter spec")
    }
  }

  // Update methods - buffer the input
  public override fun engineUpdate(
    input: ByteArray,
    inputOffset: Int,
    inputLen: Int): ByteArray? {
    buffer.write(input, inputOffset, inputLen)
    return null
  }

  public override fun engineUpdate(
    input: ByteArray,
    inputOffset: Int,
    inputLen: Int,
    output: ByteArray,
    outputOffset: Int): Int {
    buffer.write(input, inputOffset, inputLen)
    return 0
  }

  // Finalisation methods
  @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
  public override fun engineDoFinal(
    input: ByteArray,
    inputOffset: Int,
    inputLen: Int): ByteArray {
    if (inputLen != 0) {
      buffer.write(input, inputOffset, inputLen)
    }
    val `in` = buffer.toByteArray()
    buffer.reset()

    // Convert parameters for use in IESEngine
    var params: CipherParameters = IESWithCipherParameters(engineSpec!!.derivationV,
      engineSpec!!.encodingV,
      engineSpec!!.macKeySize,
      engineSpec!!.cipherKeySize)
    if (engineSpec!!.nonce != null) {
      params = ParametersWithIV(params, engineSpec!!.nonce)
    }
    val ecParams = (key as ECKeyParameters?)!!.parameters
    if (otherKeyParameter != null) {
      return try {
        if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE) {
          engine.init(true, otherKeyParameter, key, params)
        } else {
          engine.init(false, key, otherKeyParameter, params)
        }
        engine.processBlock(`in`, 0, `in`.size)
      } catch (e: Exception) {
        throw BadPaddingException(e.message)
      }
    }
    return if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE) {
      // Generate the ephemeral key pair
      val gen = ECKeyPairGenerator()
      gen.init(ECKeyGenerationParameters(ecParams, random))
      val usePointCompression = engineSpec!!.pointCompression
      val kGen = EphemeralKeyPairGenerator(gen) { keyParameter -> (keyParameter as ECPublicKeyParameters).q.getEncoded(usePointCompression) }

      // Encrypt the buffer
      try {
        engine.init(key, params, kGen)
        engine.processBlock(`in`, 0, `in`.size)
      } catch (e: Exception) {
        e.printStackTrace()
        throw BadPaddingException(e.message)
      }
    } else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE) {
      // Decrypt the buffer
      try {
        engine.init(key, params, ECIESPublicKeyParser(ecParams))
        engine.processBlock(`in`, 0, `in`.size)
      } catch (e: InvalidCipherTextException) {
        throw BadPaddingException(e.message)
      }
    } else {
      throw IllegalStateException("cipher not initialised")
    }
  }

  @Throws(ShortBufferException::class, IllegalBlockSizeException::class, BadPaddingException::class)
  public override fun engineDoFinal(
    input: ByteArray,
    inputOffset: Int,
    inputLength: Int,
    output: ByteArray,
    outputOffset: Int): Int {
    val buf = engineDoFinal(input, inputOffset, inputLength)
    System.arraycopy(buf, 0, output, outputOffset, buf.size)
    return buf.size
  }

  /**
   * Classes that inherit from us
   */
  class ECIES : IESCipher(IESEngine(ECDHBasicAgreement(),
    KDF2BytesGenerator(SHA1Digest()),
    HMac(SHA1Digest())))

  open class ECIESwithCipher : IESCipher {
    constructor(cipher: BlockCipher?) : super(IESEngine(ECDHBasicAgreement(),
      KDF2BytesGenerator(SHA1Digest()),
      HMac(SHA1Digest()),
      PaddedBufferedBlockCipher(cipher))) {
    }

    constructor(cipher: BlockCipher?, ivLength: Int) : super(IESEngine(ECDHBasicAgreement(),
      KDF2BytesGenerator(SHA1Digest()),
      HMac(SHA1Digest()),
      PaddedBufferedBlockCipher(cipher)), ivLength) {
    }
  }

  class ECIESwithDESedeCBC : ECIESwithCipher(CBCBlockCipher(DESedeEngine()), 8)
  class ECIESwithAESCBC : ECIESwithCipher(CBCBlockCipher(AESEngine()), 16)
}
