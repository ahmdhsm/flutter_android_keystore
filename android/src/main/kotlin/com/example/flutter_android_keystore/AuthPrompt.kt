package com.example.flutter_android_keystore

import android.app.Activity
import android.content.Context
import android.util.Base64
import android.widget.Toast
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import io.flutter.plugin.common.MethodChannel
import java.security.Signature
import java.util.concurrent.Executor
import javax.crypto.Cipher

class AuthPrompt {
    lateinit var activity: Activity
    lateinit var executor: Executor
    lateinit var methodChannelResult: MethodChannel.Result
    lateinit var context: Context

    private fun generatePromptInfo() : BiometricPrompt.PromptInfo {
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric login for my app")
            .setSubtitle("Log in using your biometric credential")
            .setNegativeButtonText("Use account password")
            .build()

        return promptInfo
    }

    private fun generatePrompt(
        message: ByteArray?,
        signMessage: String?,
        signature: String?
    ): BiometricPrompt {
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
                    if (message != null) {
                        val decryptedData: ByteArray? = result.cryptoObject!!.cipher?.doFinal(message)
                        methodChannelResult.success(String(decryptedData!!, Charsets.UTF_8))
                    } else if (signMessage != null && signature == null) {
                        result.cryptoObject!!.signature?.update(signMessage.toByteArray())
                        val signature = result.cryptoObject!!.signature?.sign()
                        methodChannelResult.success(Base64.encodeToString(signature, Base64.NO_WRAP))
                    } else if (signMessage != null && signature != null) {
                        result.cryptoObject!!.signature?.update(signMessage.toByteArray())
                        val verify = result.cryptoObject!!.signature?.verify(Base64.decode(signature, Base64.NO_WRAP))
                        methodChannelResult.success(verify)
                    }
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(context, "Authentication failed",
                        Toast.LENGTH_SHORT)
                        .show()
                }
            })

        return biometricPrompt
    }

    fun decryptWithAuth(cipher: Cipher, message: ByteArray?) {
        val promptInfo = generatePromptInfo()
        val biometricPrompt = generatePrompt(message, null, null)

        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }

    fun signWithAuth(signature: Signature, message: String) {
        val promptInfo = generatePromptInfo()
        val biometricPrompt = generatePrompt(null, message, null)

        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))
    }

    fun verifyWithAuth(signature: Signature, message: String, signMessage: String?) {
        val promptInfo = generatePromptInfo()
        val biometricPrompt = generatePrompt(null, message, signMessage)

        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))
    }
}