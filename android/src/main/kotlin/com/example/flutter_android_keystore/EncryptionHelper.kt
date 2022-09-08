package com.example.flutter_android_keystore

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class EncryptionHelper {
    lateinit var context: Context

    @RequiresApi(Build.VERSION_CODES.M)
    public fun encrypt(message: String, tag: String, isBiometric: Boolean): String {
        val kg: KeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

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

        val encryption = cipher.doFinal(message?.toByteArray(Charsets.UTF_8));

        Log.w("tes 1", Base64.encodeToString(encryption, Base64.NO_WRAP))
        Log.w("tes 1", encryption.decodeToString())
        Log.w("tes 1", encryption.toString())
        Log.w("tes 1", encryption[2].toString())

        return Base64.encodeToString(encryption, Base64.NO_WRAP)
    }

    @RequiresApi(Build.VERSION_CODES.KITKAT)
    public fun decrypt(message: String, tag: String, isBiometric: Boolean): String {
        val preferences = context.getSharedPreferences("MyPrefs", Context.MODE_PRIVATE)

        val byteMessage: ByteArray = Base64.decode(message, Base64.NO_WRAP);

        Log.w("tes 2", message)
        Log.w("tes 1", byteMessage[2].toString())

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

        val decodedData = cipher.doFinal(byteMessage)

        val string: String = String(decodedData, Charsets.UTF_8)

        return  string
    }
}