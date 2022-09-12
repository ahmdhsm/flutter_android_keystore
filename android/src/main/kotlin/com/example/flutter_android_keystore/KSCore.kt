package com.example.flutter_android_keystore

import android.annotation.TargetApi
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec


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
        TODO("Not yet implemented")
    }

    @RequiresApi(Build.VERSION_CODES.M)
    override fun encrypt(message: String, tag: String, password: String?): ByteArray? {
        val kg: KeyGenerator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

        val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
            tag,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        ).run {
            setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            build()
        }

        kg.init(parameterSpec)

        val sk: SecretKey = kg.generateKey()
        val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding")

        cipher.init(Cipher.ENCRYPT_MODE, sk)

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

    @RequiresApi(Build.VERSION_CODES.KITKAT)
    override fun decrypt(message: ByteArray, tag: String, password: String?): String? {
        val preferences = context.getSharedPreferences("MyPrefs", Context.MODE_PRIVATE)
        val base64Iv = preferences.getString(tag, "")
        val iv = Base64.decode(base64Iv, Base64.NO_WRAP)

        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }

        val entry: KeyStore.SecretKeyEntry = ks.getEntry(tag, null) as KeyStore.SecretKeyEntry
        val sk: SecretKey = entry.getSecretKey();
        val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding");
        val spec = GCMParameterSpec(128, iv)

        cipher.init(Cipher.DECRYPT_MODE, sk, spec)

        val decodedData = cipher.doFinal(message)
        return String(decodedData, Charsets.UTF_8)
    }

    @RequiresApi(Build.VERSION_CODES.M)
    override fun sign(tag: String, message: String, password: String?): String? {

        val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )
        val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
            tag,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).run {
            setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            build()
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