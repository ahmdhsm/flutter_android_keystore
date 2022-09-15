package com.example.flutter_android_keystore

import android.app.Activity
import android.app.Application
import android.app.KeyguardManager
import android.content.Context

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.annotation.NonNull
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

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
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import java.util.concurrent.Executor
import kotlin.math.sign


/** FlutterAndroidKeystorePlugin */
class FlutterAndroidKeystorePlugin: FlutterPlugin, MethodCallHandler, ActivityAware {
  /// The MethodChannel that will the communication between Flutter and native Android
  ///
  /// This local reference serves to register the plugin with the Flutter Engine and unregister it
  /// when the Flutter Engine is detached from the Activity
  private lateinit var channel : MethodChannel
  private lateinit var context: Context

  val encryptionHelper: EncryptionHelper = EncryptionHelper()
  val ksCore = KSCore()

  lateinit var iv: ByteArray

  private lateinit var executor: Executor
  private lateinit var biometricPrompt: BiometricPrompt
  private lateinit var promptInfo: BiometricPrompt.PromptInfo
  private lateinit var fragment: Activity
  private lateinit var keyguardManager: KeyguardManager


  override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "flutter_android_keystore")
    channel.setMethodCallHandler(this)
    encryptionHelper.context = flutterPluginBinding.applicationContext
    context = flutterPluginBinding.applicationContext
    ksCore.context = context

    executor = ContextCompat.getMainExecutor(context)

    keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
//    biometricPrompt = BiometricPrompt.PromptInfo.Builder



    promptInfo = BiometricPrompt.PromptInfo.Builder()
      .setTitle("Biometric login for my app")
      .setSubtitle("Log in using your biometric credential")
      .setNegativeButtonText("Use account password")
      .build()
  }

  override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
    if (call.method == "generateKeyPair") {
      val tag: String? = call.argument("tag")
      val encryption = ksCore.generateKeyPair(tag!!, false)

//      result.success(encryption)
    } else if (call.method == "encrypt") {
      val message: String? = call.argument("message")
      val tag: String? = call.argument("tag")

      val encryption = ksCore.encrypt(message!!, tag!!, null);

      result.success(encryption)
    } else if (call.method == "encryptWithPublicKey") {
      val message: String? = call.argument("message")
      val publicKey: String? = call.argument("publicKey")

      val encryption = ksCore.encryptWithPublicKey(message!!, publicKey!!);

      result.success(encryption)
    } else if (call.method == "decrypt") {
      val message: ByteArray? = call.argument("message")
      val tag: String? = call.argument("tag")

      val decrypt = ksCore.decrypt(message!!, tag!!, null);

      result.success(decrypt)
    } else if (call.method == "sign") {
      val plainText: String? = call.argument("plaintext")
      val tag: String? = call.argument("tag")

      val decrypt = ksCore.sign(tag!!, plainText!!, null)

      result.success(decrypt)
    } else if (call.method == "verify") {
      val plainText: String? = call.argument("plaintext")
      val tag: String? = call.argument("tag")
      val signature: String? = call.argument("signature")

      val decrypt = ksCore.verify(tag!!, plainText!!, signature!!, null);

      result.success(decrypt)
    } else if (call.method == "isKeyCreated") {
      val tag: String? = call.argument("tag")

      val keyExist = ksCore.isKeyCreated(tag!!, null)

      result.success(keyExist)
    } else if (call.method == "removeKey") {
      val tag: String? = call.argument("tag")

      val keyExist = ksCore.removeKey(tag!!)

      result.success(keyExist)
    }  else if (call.method == "getPublicKey") {
      val tag: String? = call.argument("tag")

      val publicKey = ksCore.getPublicKey(tag!!, null)

      result.success(publicKey)
    } else {
      result.notImplemented()
    }
  }

  override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
  }

  override fun onAttachedToActivity(binding: ActivityPluginBinding) {
    fragment = binding.activity
  }

  override fun onDetachedFromActivityForConfigChanges() {
    TODO("Not yet implemented")
  }

  override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
    TODO("Not yet implemented")
  }

  override fun onDetachedFromActivity() {
    TODO("Not yet implemented")
  }
}
