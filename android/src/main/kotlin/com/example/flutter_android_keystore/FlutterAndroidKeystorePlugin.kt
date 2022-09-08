package com.example.flutter_android_keystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.annotation.NonNull
import androidx.annotation.RequiresApi

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.nio.charset.Charset
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** FlutterAndroidKeystorePlugin */
class FlutterAndroidKeystorePlugin: FlutterPlugin, MethodCallHandler {
  /// The MethodChannel that will the communication between Flutter and native Android
  ///
  /// This local reference serves to register the plugin with the Flutter Engine and unregister it
  /// when the Flutter Engine is detached from the Activity
  private lateinit var channel : MethodChannel

  lateinit var iv: ByteArray

  override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "flutter_android_keystore")
    channel.setMethodCallHandler(this)
  }

  @RequiresApi(Build.VERSION_CODES.M)
  override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
//    var iv: ByteArray

    if (call.method == "getPlatformVersion") {
//      result.success("Android ${android.os.Build.VERSION.RELEASE}")
            val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_EC,
        "AndroidKeyStore"
      )
//      val kg: KeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeystore")

            val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
        "alias",
        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
      ).run {
        setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
        build()
      }

      kpg.initialize(parameterSpec)

      val kp = kpg.generateKeyPair()

//      val sc: SecretKey = kg.generateKey();


//      val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
//        KeyProperties.KEY_ALGORITHM_EC,
//        "AndroidKeyStore"
//      )
//      val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
//        "alias",
//        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
//      ).run {
//        setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
//        build()
//      }
//
//      kpg.initialize(parameterSpec)
//
//      val kp = kpg.generateKeyPair()
//
//
      val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
      }
      val entry: KeyStore.Entry = ks.getEntry("alias", null)
      if (entry !is KeyStore.PrivateKeyEntry) {
        Log.w("tes", "Not an instance of a PrivateKeyEntry")
        return
      }
      val signature: ByteArray = Signature.getInstance("SHA256withECDSA").run {
        initSign(entry.privateKey)
        update(123)
        sign()
      }

      val valid: Boolean = Signature.getInstance("SHA256withECDSA").run {
        initVerify(entry.certificate)
        update(1)
        verify(signature)
      }
      result.success(valid.toString())
    } else if (call.method == "encrypt") {
      val kg: KeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

      val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
        "alias",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
      ).run {
        setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        build()
      }

      kg.init(parameterSpec)

      val sk: SecretKey = kg.generateKey();

      val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding");

      cipher.init(Cipher.ENCRYPT_MODE, sk);

      val message: String? = call.argument("message");

      iv = cipher.getIV()

      val encryption = cipher.doFinal(message?.toByteArray(Charsets.UTF_8));

      result.success(encryption)
    } else if (call.method == "decrypt") {
      val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
      }

      val entry: KeyStore.SecretKeyEntry = ks.getEntry("alias", null) as KeyStore.SecretKeyEntry

      val sk: SecretKey = entry.getSecretKey();

      val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding");
      val spec = GCMParameterSpec(128, iv)

      cipher.init(Cipher.DECRYPT_MODE, sk, spec)

      val message: ByteArray? = call.argument("message");

      val decodedData = cipher.doFinal(message)

      val string: String = String(decodedData, Charsets.UTF_8)

      result.success(string)
    } else {
      result.notImplemented()
    }
  }

  override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
  }
}
