package com.example.flutter_android_keystore

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec


abstract class KSCoreAbstract {
    // create and store private key to secure enclave
    abstract fun generateKeyPair(tag: String, biometric: Boolean) : KeyPair?

    // remove key from secure enclave
    abstract fun removeKey(tag: String) : Boolean

    // get SecKey key from secure enclave (private method)
    abstract  fun getSecKey(tag: String, password: String?) : SecretKey

    // get status SecKey key from secure enclave (private method)
    abstract fun isKeyCreated(tag: String, password: String?) : Boolean?

    // get publicKey key from secure enclave
    abstract fun getPublicKey(tag: String, password: String?) : String?

    // encryption
    abstract fun encrypt(message: String, tag: String, password: String?) : ByteArray?

    // encryption with base64 Public key
    abstract fun encryptWithPublicKey(message: String, publicKey: String) : ByteArray?

    // decryption
    abstract fun decrypt(message: ByteArray, tag: String, password: String?) : String?

    // sign
    abstract fun sign(tag: String, message: String, password: String?) : String?

    // verify
    abstract fun verify(tag: String, plainText: String, signature: String, password: String?) : Boolean
}

class KSCore() : KSCoreAbstract() {
    lateinit var context: Context

    override fun generateKeyPair(tag: String, biometric: Boolean): KeyPair? {
        val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore",
        )
        val spec: AlgorithmParameterSpec

        var specRSA = RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4)

        val parameterSpec: KeyGenParameterSpec.Builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            KeyGenParameterSpec.Builder(
                tag,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_VERIFY
            )
        } else {
            TODO("VERSION.SDK_INT < M")
        }

        parameterSpec.setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        parameterSpec.setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            parameterSpec.setIsStrongBoxBacked(true)
        }

        spec = parameterSpec.run {
            setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            setUserAuthenticationRequired(biometric)
            build()
        }

        kpg.initialize(spec)

        val kp = kpg.generateKeyPair()
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

    override fun encrypt(message: String, tag: String, password: String?): ByteArray? {
        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }

//        val entry: KeyStore.SecretKeyEntry = ks.getEntry(tag, null) as KeyStore.SecretKeyEntry
//        val sk: SecretKey = entry.getSecretKey()

        val certificate = ks.getCertificate(tag)

//        val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding")

        val cipher: Cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")

        cipher.init(Cipher.ENCRYPT_MODE, certificate.publicKey)

        val iv = cipher.getIV()
        val editor = context.getSharedPreferences("MyPrefs", Context.MODE_PRIVATE).edit()
        val ivString = Base64.encodeToString(iv, Base64.NO_WRAP)
        editor.putString(tag, ivString)
        editor.commit()

        return cipher.doFinal(message?.toByteArray(Charsets.UTF_8))
    }

    override fun encryptWithPublicKey(message: String, publicKey: String): ByteArray? {
        TODO("Not yet implemented")
    }

    override fun decrypt(message: ByteArray, tag: String, password: String?): String? {
        val preferences = context.getSharedPreferences("MyPrefs", Context.MODE_PRIVATE)
        val base64Iv = preferences.getString(tag, "")
        val iv = Base64.decode(base64Iv, Base64.NO_WRAP)

        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }

        val entry: KeyStore.SecretKeyEntry = ks.getEntry(tag, null) as KeyStore.SecretKeyEntry
        val sk: SecretKey = entry.getSecretKey();
        val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding")

        val spec = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            GCMParameterSpec(128, iv)
        } else {
            TODO("VERSION.SDK_INT < KITKAT")
        }

        cipher.init(Cipher.DECRYPT_MODE, sk, spec)

        val decodedData = cipher.doFinal(message)
        return String(decodedData, Charsets.UTF_8)
    }

    override fun sign(tag: String, message: String, password: String?): String? {
        val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )
        val parameterSpec: KeyGenParameterSpec = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            KeyGenParameterSpec.Builder(
                tag,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).run {
                setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                build()
            }
        } else {
            TODO("VERSION.SDK_INT < M")
        }

        kpg.initialize(parameterSpec)

        val kp = kpg.generateKeyPair()

        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }
        val entry: KeyStore.Entry = ks.getEntry(tag, null)
        if (entry !is KeyStore.PrivateKeyEntry) {
            return null
        }

        val signature: ByteArray = Signature.getInstance("SHA256withECDSA").run {
            initSign(entry.privateKey)
            update(message.toByteArray())
            sign()
        }

        return Base64.encodeToString(signature, Base64.NO_WRAP)
    }

    override fun verify(
        tag: String,
        plainText: String,
        signature: String,
        password: String?
    ): Boolean {
        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }
        val entry: KeyStore.Entry = ks.getEntry(tag, null)
        if (entry !is KeyStore.PrivateKeyEntry) {
            return false
        }

        val valid: Boolean = Signature.getInstance("SHA256withECDSA").run {
            initVerify(entry.certificate)
            update(plainText.toByteArray())
            verify(Base64.decode(signature, Base64.NO_WRAP))
        }

        return valid
    }

}