package com.example.flutter_android_keystore

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
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
            KeyProperties.KEY_ALGORITHM_RSA,
            "AndroidKeyStore",
        )
        val spec: AlgorithmParameterSpec

        var specRSA = RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4)

        val parameterSpec: KeyGenParameterSpec.Builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            KeyGenParameterSpec.Builder(
                tag,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
        } else {
            TODO("VERSION.SDK_INT < M")
        }

//        parameterSpec.setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        parameterSpec.setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            parameterSpec.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                parameterSpec.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)

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
        Log.d("tes 2", Base64.encodeToString(chiper, Base64.NO_WRAP))
        return chiper
    }

    override fun encryptWithPublicKey(message: String, publicKey: String): ByteArray? {
        TODO("Not yet implemented")
    }

    override fun decrypt(message: ByteArray, tag: String, password: String?): String? {
        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }

//        val chars = arrayOf('A', 'B', 'C') as CharArray
        val pk = ks.getKey(tag, null)

//        val entry: KeyStore.SecretKeyEntry = ks.getEntry(tag, null) as KeyStore.SecretKeyEntry
//        val sk: SecretKey = entry.getSecretKey();
        val cipher: Cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding")

//        val spec = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
//            GCMParameterSpec(128, iv)
//        } else {
//            TODO("VERSION.SDK_INT < KITKAT")
//        }
        val sp = OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec("SHA-1"),
            PSource.PSpecified.DEFAULT
        )
        cipher.init(Cipher.DECRYPT_MODE, pk, sp)

        Log.d("tes 1", Base64.encodeToString(message, Base64.NO_WRAP))

        val decodedData = cipher.doFinal(message)
        return String(decodedData, Charsets.UTF_8)
    }

    override fun sign(tag: String, message: String, password: String?): String? {
//        val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
//            KeyProperties.KEY_ALGORITHM_EC,
//            "AndroidKeyStore"
//        )
//        val parameterSpec: KeyGenParameterSpec = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
//            KeyGenParameterSpec.Builder(
//                tag,
//                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
//            ).run {
//                setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
//                build()
//            }
//        } else {
//            TODO("VERSION.SDK_INT < M")
//        }
//
//        kpg.initialize(parameterSpec)
//
//        val kp = kpg.generateKeyPair()

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

//        val signature = Signature.getInstance("SHA256withRSA/PSS")
//        signature.initSign(ks.getKey(tag, null) as PrivateKey)

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