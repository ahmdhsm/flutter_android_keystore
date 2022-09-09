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
  var verifyTextController = TextEditingController();

  Uint8List? chiperByte;
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
        body: Center(
          child: Column(
            children: [
              TextFormField(
                controller: plainTextController,
              ),
              const SizedBox(height: 10),
              ElevatedButton(
                onPressed: () async {
                  ResultModel result = await androidKeystore.encrypt(
                      message: plainTextController.text, tag: "Tag");
                  chiperByte = result.rawData;
                  print(base64Encode(chiperByte!));
                  encryptedTextController.text = chiperByte.toString();
                },
                child: const Text('Encrypt'),
              ),
              TextFormField(
                controller: encryptedTextController,
              ),
              const SizedBox(height: 10),
              ElevatedButton(
                onPressed: () async {
                  ResultModel result = await androidKeystore.decrypt(
                    message: chiperByte!,
                    tag: "Tag",
                  );
                  decryptedTextController.text = result.rawData;
                },
                child: const Text('Decrypt'),
              ),
              TextFormField(
                controller: decryptedTextController,
              ),
              TextFormField(
                controller: signTextController,
              ),
              const SizedBox(height: 10),
              ElevatedButton(
                onPressed: () async {
                  ResultModel result = await androidKeystore.sign(
                    message:
                        Uint8List.fromList(signTextController.text.codeUnits),
                    tag: "Tag",
                  );
                  decryptedTextController.text = result.rawData;
                },
                child: const Text('Sign'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
