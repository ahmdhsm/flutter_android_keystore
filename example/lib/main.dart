import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_android_keystore/android_keystore_base.dart';
import 'package:flutter_android_keystore/flutter_android_keystore.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String _platformVersion = 'Unknown';

  var androidKeystore = FlutterAndroidKeystore();

  var plainTextController = TextEditingController();
  var encryptedTextController = TextEditingController();
  var decryptedTextController = TextEditingController();
  var signTextController = TextEditingController();
  var signResultTextController = TextEditingController();
  var verifyTextController = TextEditingController();
  var verifyResultTextController = TextEditingController();
  var publicKeyTextController = TextEditingController();
  var encryptedWithPublickKeyTextController = TextEditingController();
  var decryptedFromPublicKeyTextEditingController = TextEditingController();

  Uint8List? chiperByte;
  Uint8List? chiperFromPublicKey;
  String? signature;
  String encrypted = "";

  @override
  void initState() {
    super.initState();
  }

  // Platform messages are asynchronous, so we initialize in an async method.
  Future<void> initPlatformState() async {
    String platformVersion;
    // Platform messages may fail, so we use a try/catch PlatformException.
    // We also handle the message potentially returning null.
    try {
      platformVersion = await FlutterAndroidKeystore.platformVersion ??
          'Unknown platform version';
    } on PlatformException {
      platformVersion = 'Failed to get platform version.';
    }

    // If the widget was removed from the tree while the asynchronous platform
    // message was in flight, we want to discard the reply rather than calling
    // setState to update our non-existent appearance.
    if (!mounted) return;

    setState(() {
      _platformVersion = platformVersion;
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
        ),
        body: SingleChildScrollView(
          child: Padding(
            padding: EdgeInsets.symmetric(horizontal: 10),
            child: Column(
              children: [
                ElevatedButton(
                  onPressed: () async {
                    ResultModel result = await androidKeystore.generateKeyPair(
                      accessControl: AccessControlModel(
                          options: [], tag: "Tag.AppBiometric"),
                    );
                  },
                  child: const Text('Generate Key Pair'),
                ),
                ElevatedButton(
                  onPressed: () async {
                    ResultModel result = await androidKeystore.getPublicKey(
                        tag: 'Tag.AppBiometric');
                  },
                  child: const Text('Get Public Key'),
                ),
                TextFormField(
                  controller: plainTextController,
                  decoration: const InputDecoration(
                    label: Text('Text'),
                  ),
                ),
                const SizedBox(height: 10),
                ElevatedButton(
                  onPressed: () async {
                    ResultModel result = await androidKeystore.encrypt(
                        message: plainTextController.text,
                        tag: "Tag.AppBiometric");
                    chiperByte = result.rawData;
                    encryptedTextController.text = chiperByte.toString();
                  },
                  child: const Text('Encrypt'),
                ),
                TextFormField(
                  controller: encryptedTextController,
                  decoration: const InputDecoration(
                    label: Text('Encrypted'),
                  ),
                  enabled: false,
                ),
                const SizedBox(height: 10),
                ElevatedButton(
                  onPressed: () async {
                    ResultModel result = await androidKeystore.decrypt(
                      message: chiperByte!,
                      tag: "Tag.AppBiometric",
                    );
                    decryptedTextController.text = result.rawData;
                  },
                  child: const Text('Decrypt'),
                ),
                TextFormField(
                  controller: decryptedTextController,
                  decoration: const InputDecoration(
                    label: Text('Decrypted'),
                  ),
                  enabled: false,
                ),
                TextFormField(
                  controller: publicKeyTextController,
                  decoration: const InputDecoration(
                    label: Text('Public Key'),
                  ),
                ),
                ElevatedButton(
                  onPressed: () async {
                    ResultModel result =
                        await androidKeystore.encryptWithPublicKey(
                      message: plainTextController.text,
                      publicKey: publicKeyTextController.text,
                    );
                    chiperFromPublicKey = result.rawData;
                    encryptedWithPublickKeyTextController.text =
                        result.rawData.toString();
                  },
                  child: const Text('Encrypt With Public Key'),
                ),
                TextFormField(
                  controller: encryptedWithPublickKeyTextController,
                  decoration: const InputDecoration(
                    label: Text('Encrypted With Public Key'),
                  ),
                  enabled: false,
                ),
                ElevatedButton(
                  onPressed: () async {
                    ResultModel result = await androidKeystore.decrypt(
                      message: chiperByte!,
                      tag: "Tag",
                    );
                    decryptedFromPublicKeyTextEditingController.text =
                        result.rawData;
                  },
                  child: const Text('Decrypt From Public Key'),
                ),
                TextFormField(
                  controller: decryptedFromPublicKeyTextEditingController,
                  decoration: const InputDecoration(
                    label: Text('Decrypted From Public Key'),
                  ),
                  enabled: false,
                ),
                TextFormField(
                  controller: signTextController,
                  decoration: const InputDecoration(
                    label: Text('Signature Text'),
                  ),
                ),
                const SizedBox(height: 10),
                ElevatedButton(
                  onPressed: () async {
                    ResultModel result = await androidKeystore.sign(
                      message:
                          Uint8List.fromList(signTextController.text.codeUnits),
                      tag: "Tag.AppBiometric",
                    );
                    signature = result.rawData;
                    signResultTextController.text = signature.toString();
                  },
                  child: const Text('Sign'),
                ),
                TextFormField(
                  controller: signResultTextController,
                  decoration: const InputDecoration(
                    label: Text('Signature Result'),
                  ),
                  enabled: false,
                ),
                TextFormField(
                  controller: verifyTextController,
                  decoration: const InputDecoration(
                    label: Text('Verify Text'),
                  ),
                ),
                ElevatedButton(
                  onPressed: () async {
                    ResultModel result = await androidKeystore.verify(
                      plainText: verifyTextController.text,
                      signature: signature!,
                      tag: "Tag.AppBiometric",
                    );
                    verifyResultTextController.text = result.rawData.toString();
                  },
                  child: const Text('verify'),
                ),
                TextFormField(
                  controller: verifyResultTextController,
                  decoration: const InputDecoration(
                    label: Text('Verify Result'),
                  ),
                  enabled: false,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
