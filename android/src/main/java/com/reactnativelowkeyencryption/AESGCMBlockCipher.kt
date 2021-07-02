package com.reactnativelowkeyencryption

import org.bouncycastle.crypto.BufferedBlockCipher
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher


class AESGCMBlockCipher : BufferedBlockCipher() {
  private val internalCipher: GCMBlockCipher
  override fun init(forEncryption: Boolean, params: CipherParameters) {
    internalCipher.init(forEncryption, params)
  }

  override fun getOutputSize(len: Int): Int {
    return internalCipher.getOutputSize(len)
  }

  @Throws(InvalidCipherTextException::class)
  override fun doFinal(out: ByteArray, outOff: Int): Int {
    return internalCipher.doFinal(out, outOff)
  }

  override fun processBytes(`in`: ByteArray, inOff: Int, len: Int, out: ByteArray, outOff: Int): Int {
    return internalCipher.processBytes(`in`, inOff, len, out, outOff)
  }

  init {
    internalCipher = GCMBlockCipher(AESEngine())
  }
}
