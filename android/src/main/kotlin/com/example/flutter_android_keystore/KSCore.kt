package com.example.flutter_android_keystore

import android.annotation.SuppressLint
import android.annotation.TargetApi
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import javax.crypto.SecretKey


abstract class KSCoreAbstract {
    // create and store private key to secure enclave
    abstract fun generateKeyPair() : KeyPair?

    // remove key from secure enclave
    abstract fun removeKey(tag: String) : Boolean

    // get SecKey key from secure enclave (private method)
    abstract  fun getSecKey(tag: String, password: String?) : SecretKey

    // get status SecKey key from secure enclave (private method)
    abstract fun isKeyCreated(tag: String, password: String?) : Boolean?

    // get publicKey key from secure enclave
    abstract fun getPublicKey(tag: String, password: String?) : String?

    // encryption
    abstract fun encrypt(message: String, tag: String, password: String?) : List<Int>?

    // encryption with base64 Public key
    abstract fun encryptWithPublicKey(message: String, publicKey: String) : List<Int>?

    // decryption
    abstract fun decrypt(message: ByteArray, tag: String, password: String?) : String?

    // sign
    abstract fun sign(tag: String, password: String?, message: String) : String?

    // verify
    abstract fun verify(tag: String, password: String?, plainText: String, signature: String) : Boolean
}

class KSCore(private var context: Context) : KSCoreAbstract() {
    @TargetApi(Build.VERSION_CODES.M)
    override fun generateKeyPair(): KeyPair? {
        val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore",
        )
        val spec: AlgorithmParameterSpec

        val parameterSpec: KeyGenParameterSpec.Builder = KeyGenParameterSpec.Builder(
            "alias",
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_VERIFY
        )

        parameterSpec.setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        parameterSpec.setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            parameterSpec.setIsStrongBoxBacked(true)
        }

        spec = parameterSpec.run {
            setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            build()
        }

        kpg.initialize(spec)

        val kp = kpg.generateKeyPair()
        println("wsws" + kp.private.encoded)
        println("wkwk" + kp.public.encoded)
        return kp
    }

    override fun removeKey(tag: String): Boolean {
        TODO("Not yet implemented")
    }

    override fun getSecKey(tag: String, password: String?): SecretKey {
        TODO("Not yet implemented")
    }

    override fun isKeyCreated(tag: String, password: String?): Boolean? {
        TODO("Not yet implemented")
    }

    override fun getPublicKey(tag: String, password: String?): String? {
        TODO("Not yet implemented")
    }

    override fun encrypt(message: String, tag: String, password: String?): List<Int>? {
        TODO("Not yet implemented")
    }

    override fun encryptWithPublicKey(message: String, publicKey: String): List<Int>? {
        TODO("Not yet implemented")
    }

    override fun decrypt(message: ByteArray, tag: String, password: String?): String? {
        TODO("Not yet implemented")
    }

    override fun sign(tag: String, password: String?, message: String): String? {
        TODO("Not yet implemented")
    }

    override fun verify(
        tag: String,
        password: String?,
        plainText: String,
        signature: String
    ): Boolean {
        TODO("Not yet implemented")
    }

}