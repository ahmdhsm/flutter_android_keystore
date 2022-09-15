package com.example.flutter_android_keystore

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.security.*
import java.security.spec.*
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource


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
    abstract fun decrypt(message: ByteArray, tag: String, password: String?) : Cipher?

    // sign
    abstract fun sign(tag: String, message: String, password: String?) : String?

    // verify
    abstract fun verify(tag: String, plainText: String, signature: String, password: String?) : Boolean
}

class KSCore() : KSCoreAbstract() {
    lateinit var context: Context

    override fun generateKeyPair(tag: String, biometric: Boolean): KeyPair? {
        val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            "AndroidKeyStore",
        )
        val spec: AlgorithmParameterSpec

//        var specRSA = RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4)

        val parameterSpec: KeyGenParameterSpec.Builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            KeyGenParameterSpec.Builder(
                tag,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
        } else {
            TODO("VERSION.SDK_INT < M")
        }




        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            parameterSpec.setIsStrongBoxBacked(true)
        }

        spec = parameterSpec.run {
            setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            setUserAuthenticationRequired(biometric)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
            build()
        }

        kpg.initialize(spec)

        val kp = kpg.generateKeyPair()
        return kp
    }

    override fun removeKey(tag: String): Boolean {
        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }

        if (ks.containsAlias(tag)) {
            ks.deleteEntry(tag)
            return true
        }

        return false
    }

    override fun getSecKey(tag: String, password: String?): SecretKey {
        TODO("Not yet implemented")
    }

    override fun isKeyCreated(tag: String, password: String?): Boolean? {
        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }

        if (ks.containsAlias(tag)) {
            return true
        }
        return false
    }

    override fun getPublicKey(tag: String, password: String?): String? {
        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }

        val publicKey = ks.getCertificate(tag).publicKey
        return Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP)
    }

    override fun encrypt(message: String, tag: String, password: String?): ByteArray? {
        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }

        val certificate = ks.getCertificate(tag)

        val cipher: Cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding")

        val sp = OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec("SHA-1"),
            PSource.PSpecified.DEFAULT
        )

        cipher.init(Cipher.ENCRYPT_MODE, certificate.publicKey, sp)

        val chiper =  cipher.doFinal(message?.toByteArray(Charsets.UTF_8))
        return chiper
    }

    override fun encryptWithPublicKey(message: String, publicKey: String): ByteArray? {
        val data: ByteArray = Base64.decode(publicKey, Base64.DEFAULT)
        val spec = X509EncodedKeySpec(data)
        val fact = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA)
        val pk = fact.generatePublic(spec)

        val cipher: Cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding")

        val sp = OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec("SHA-1"),
            PSource.PSpecified.DEFAULT
        )

        cipher.init(Cipher.ENCRYPT_MODE, pk, sp)

        val chiper =  cipher.doFinal(message?.toByteArray(Charsets.UTF_8))
        return chiper
    }

    override fun decrypt(message: ByteArray, tag: String, password: String?): Cipher? {
        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }

        val pk = ks.getKey(tag, null)

        val cipher: Cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding")

        val sp = OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec("SHA-1"),
            PSource.PSpecified.DEFAULT
        )

        cipher.init(Cipher.DECRYPT_MODE, pk, sp)

        return  cipher

//        if (tag.contains("AppWithoutAuth")) {
//            val decodedData = cipher.doFinal(message)
//            return String(decodedData!!, Charsets.UTF_8)
//        }
//
//        val promptInfo = generatePromptInfo()
//        val biometricPrompt = generateBiometricPrompt(message)
//        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher!!))
//        return String(decodedData!!, Charsets.UTF_8)
    }

    override fun sign(tag: String, message: String, password: String?): String? {
        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }
        val entry: KeyStore.Entry = ks.getEntry(tag, null)
        if (entry !is KeyStore.PrivateKeyEntry) {
            return null
        }

        val signature: ByteArray = Signature.getInstance("SHA256withRSA/PSS").run {
            initSign(ks.getKey(tag, null) as PrivateKey)
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

        val valid: Boolean = Signature.getInstance("SHA256withRSA/PSS").run {
            initVerify(entry.certificate)
            update(plainText.toByteArray())
            verify(Base64.decode(signature, Base64.NO_WRAP))
        }

        return valid
    }

}