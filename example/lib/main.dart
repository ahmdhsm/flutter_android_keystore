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
  Uint8List? chiper;
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
                  chiper = result.rawData;
                  encryptedTextController.text =
                      (result.rawData as Uint8List).toString();
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
                      message: chiper!, tag: "Tag");
                  decryptedTextController.text = result.rawData;
                },
                child: const Text('Encrypt'),
              ),
              TextFormField(
                controller: decryptedTextController,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
