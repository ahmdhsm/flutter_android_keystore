// You have generated a new plugin project without
// specifying the `--platforms` flag. A plugin project supports no platforms is generated.
// To add platforms, run `flutter create -t plugin --platforms <platforms> .` under the same
// directory. You can also find a detailed instruction on how to add platforms in the `pubspec.yaml` at https://flutter.dev/docs/development/packages-and-plugins/developing-packages#plugin-platforms.

import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/services.dart';
import 'package:flutter_android_keystore/src/models/result_model.dart';
import 'package:flutter_android_keystore/src/models/access_control_model.dart';

import 'android_keystore_base.dart';

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
    final String? data =
        await _channel.invokeMethod('decrypt', {"message": message});
    final result = ResultModel(null, data, (dynamic) {});
    return result;
  }

  @override
  Future<ResultModel<Uint8List?>> encrypt(
      {required String message, required String tag, String? password}) async {
    final Uint8List data =
        await _channel.invokeMethod('encrypt', {"message": message});
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
      {required AccessControlModel accessControl}) {
    // TODO: implement generateKeyPair
    throw UnimplementedError();
  }

  @override
  Future<ResultModel<String?>> getPublicKey(
      {required String tag, String? password}) {
    // TODO: implement getPublicKey
    throw UnimplementedError();
  }

  @override
  Future<ResultModel<bool?>> isKeyCreated(
      {required String tag, String? password}) {
    // TODO: implement isKeyCreated
    throw UnimplementedError();
  }

  @override
  Future<ResultModel<bool>> removeKey(String tag) {
    // TODO: implement removeKey
    throw UnimplementedError();
  }

  @override
  Future<ResultModel<String?>> sign(
      {required Uint8List message, required String tag, String? password}) {
    // TODO: implement sign
    throw UnimplementedError();
  }

  @override
  Future<ResultModel<bool?>> verify(
      {required String plainText,
      required String signature,
      required String tag,
      String? password}) {
    // TODO: implement verify
    throw UnimplementedError();
  }
}
