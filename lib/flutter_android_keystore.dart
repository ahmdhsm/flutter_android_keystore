// You have generated a new plugin project without
// specifying the `--platforms` flag. A plugin project supports no platforms is generated.
// To add platforms, run `flutter create -t plugin --platforms <platforms> .` under the same
// dirctory. You can also find a detailed instruction on how to add platforms in the `pubspec.yaml` at https://flutter.dev/docs/development/packages-and-plugins/developing-packages#plugin-platforms.

import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:flutter/services.dart';
import 'package:flutter_android_keystore/src/models/result_model.dart';
import 'package:flutter_android_keystore/src/models/access_control_model.dart';

import 'android_keystore_base.dart';

export 'package:flutter_android_keystore/src/models/access_control_model.dart';

class FlutterAndroidKeystore implements AndroidKeystoreBase {
  static const MethodChannel _channel =
      MethodChannel('flutter_android_keystore');

  static Future<String?> get platformVersion async {
    final String? version = await _channel.invokeMethod('getPlatformVersion');
    return version;
  }

  @override
  Future<ResultModel<String?>> decrypt(
      {required Uint8List message,
      required String tag,
      String? password}) async {
    final String? data = await _channel
        .invokeMethod('decrypt', {"message": message, "tag": tag});
    final result = ResultModel(null, data, (dynamic) {});
    return result;
  }

  @override
  Future<ResultModel<Uint8List?>> encrypt(
      {required String message, required String tag, String? password}) async {
    final Uint8List data = await _channel
        .invokeMethod('encrypt', {"message": message, "tag": tag});
    final result = ResultModel(null, data, (dynamic) {});
    return result;
  }

  @override
  Future<ResultModel<Uint8List?>> encryptWithPublicKey(
      {required String message, required String publicKey}) {
    // TODO: implement encryptWithPublicKey
    throw UnimplementedError();
  }

  @override
  Future<ResultModel<bool>> generateKeyPair(
      {required AccessControlModel accessControl}) async {
    final String data = await _channel
        .invokeMethod('generateKeyPair', {"tag": accessControl.tag});
    final result = ResultModel(null, data, (dynamic) {});
    return result.rawData;
  }

  @override
  Future<ResultModel<String?>> getPublicKey(
      {required String tag, String? password}) async {
    final String data =
        await _channel.invokeMethod('getPublicKey', {"tag": tag});
    final result = ResultModel(null, data, (dynamic) {});
    print(result.rawData);
    return result;
  }

  @override
  Future<ResultModel<bool?>> isKeyCreated(
      {required String tag, String? password}) async {
    final bool data = await _channel.invokeMethod('isKeyCreated', {"tag": tag});
    final result = ResultModel(null, data, (dynamic) {});
    return result;
  }

  @override
  Future<ResultModel<bool>> removeKey(String tag) async {
    final bool data = await _channel.invokeMethod('removeKey', {"tag": tag});
    final result = ResultModel<bool>(null, data, (dynamic) {
      return false;
    });
    return result;
  }

  @override
  Future<ResultModel<String?>> sign({
    required Uint8List message,
    required String tag,
    String? password,
  }) async {
    var stringMessage = utf8.decode(message);
    final String data = await _channel
        .invokeMethod('sign', {"plaintext": stringMessage, "tag": tag});
    final result = ResultModel(null, data, (dynamic) {});
    return result;
  }

  @override
  Future<ResultModel<bool?>> verify(
      {required String plainText,
      required String signature,
      required String tag,
      String? password}) async {
    final bool data = await _channel.invokeMethod(
        'verify', {"plaintext": plainText, "tag": tag, "signature": signature});
    final result = ResultModel(null, data, (dynamic) {});
    return result;
  }
}
