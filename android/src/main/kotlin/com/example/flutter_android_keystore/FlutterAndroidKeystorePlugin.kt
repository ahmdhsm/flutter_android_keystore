package com.example.flutter_android_keystore

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.util.Log
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.Toast
import androidx.annotation.NonNull
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.nio.charset.Charset
import java.util.*
import java.util.concurrent.Executor


/** FlutterAndroidKeystorePlugin */
class FlutterAndroidKeystorePlugin: FlutterPlugin, MethodCallHandler, ActivityAware {
  /// The MethodChannel that will the communication between Flutter and native Android
  ///
  /// This local reference serves to register the plugin with the Flutter Engine and unregister it
  /// when the Flutter Engine is detached from the Activity
  private lateinit var channel : MethodChannel
  private lateinit var context: Context
  private lateinit var plainText: ByteArray

  private lateinit var activity: Activity
  private lateinit var executor: Executor

  val ksCore = KSCore()

  lateinit var iv: ByteArray


  override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "flutter_android_keystore")
    channel.setMethodCallHandler(this)

    context = flutterPluginBinding.applicationContext
    executor = ContextCompat.getMainExecutor(context)

    ksCore.context = context
  }

  override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
    if (call.method == "generateKeyPair") {
      val tag: String? = call.argument("tag")
      if (tag!!.contains(".AppBiometric")) {
        ksCore.generateKeyPair(tag!!, true)
      } else {
        ksCore.generateKeyPair(tag!!, false)
      }
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
      val tes: MethodChannel.Result = result
      val message: ByteArray? = call.argument("message")
      val tag: String? = call.argument("tag")

      val cipher = ksCore.decrypt(message!!, tag!!, null)

      if (tag.contains("AppBiometric")) {
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
          .setTitle("Biometric login for my app")
          .setSubtitle("Log in using your biometric credential")
          .setNegativeButtonText("Use account password")
          .build()

        val biometricPrompt = BiometricPrompt(activity as FragmentActivity, executor,
          object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int,
                                               errString: CharSequence) {
              super.onAuthenticationError(errorCode, errString)
              Toast.makeText(context,
                "Authentication error: $errString", Toast.LENGTH_SHORT)
                .show()
            }

            override fun onAuthenticationSucceeded(
              result: BiometricPrompt.AuthenticationResult) {
              super.onAuthenticationSucceeded(result)
              val decryptedData: ByteArray? = result.cryptoObject!!.cipher?.doFinal(
                message
              )
              tes.success(String(decryptedData!!, Charsets.UTF_8))
            }

            override fun onAuthenticationFailed() {
              super.onAuthenticationFailed()
              Toast.makeText(context, "Authentication failed",
                Toast.LENGTH_SHORT)
                .show()
            }
          })

        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher!!))
      } else {
        val decodedData = cipher!!.doFinal(message)
        String(decodedData!!, Charsets.UTF_8)
        result.success("kkk")
      }
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
    activity = binding.activity
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
