import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:flutter/material.dart';

void main() => runApp(MyApp());
class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter',
      home: Scaffold(
        appBar: AppBar(
          title: Text('Flutter Console'),
        ),
        body: MyWidget(),
      ),
    );
  }
}

// widget class
class MyWidget extends StatefulWidget {
  @override
  _MyWidgetState createState() => _MyWidgetState();
}

class _MyWidgetState extends State<MyWidget> {
  // state variable
  String _textString = 'press the button "run the code"';
  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Text(
          'console output',
          style: TextStyle(fontSize: 30),
        ),
        Expanded(
          flex: 1,
          child: new SingleChildScrollView(
            scrollDirection: Axis.vertical,
            child: Padding(
                padding: EdgeInsets.fromLTRB(10, 5, 10, 5),
                child: Text(_textString,
                    style: TextStyle(
                      fontSize: 20.0,
                      fontWeight: FontWeight.bold,
                      fontFamily: 'Courier',
                      color: Colors.black,
                    ))),
          ),
        ),
        Container(
          child: Row(
            children: <Widget>[
              SizedBox(width: 10),
              Expanded(
                child: ElevatedButton(
                  child: Text('clear console'),
                  onPressed: () {
                    clearConsole();
                  },
                ),
              ),
              SizedBox(width: 10),
              Expanded(
                child: ElevatedButton(
                  child: Text('extra Button'),
                  onPressed: () {
                    runYourSecondDartCode();
                  },
                ),
              ),
              SizedBox(width: 10),
              Expanded(
                child: ElevatedButton(
                  child: Text('run the code'),
                  onPressed: () {
                    runYourMainDartCode();
                  },
                ),
              ),
              SizedBox(width: 10),
            ],
          ),
        ),
      ],
    );
  }

  void clearConsole() {
    setState(() {
      _textString = ''; // will add additional lines
    });
  }

  void printC(_newString) {
    setState(() {
      _textString =
          _textString + _newString + '\n';
    });
  }
  /* ### instructions ###
      place your code inside runYourMainDartCode and print it to the console
      using printC('your output to the console');
      clearConsole() clears the actual console
      place your code that needs to be executed additionally inside
      runYourSecondDartCode and start it with "extra Button"
   */
  void runYourMainDartCode() {

    clearConsole();

    // lib for ECDH
    // https://pub.dev/packages/elliptic elliptic: ^0.3.6
    // https://github.com/C0MM4ND/dart-elliptic

    // lib for Blake2b and AES GCM:
    // https://pub.dev/packages/pointycastle pointycastle: ^3.5.2
    // https://github.com/bcgit/pc-dart

/*
curce P521 runs an error in computeSecret:
======== Exception caught by gesture ===============================================================
The following RangeError was thrown while handling a gesture:
RangeError (end): Invalid value: Not in inclusive range 130..131: 132

When the exception was thrown, this was the stack:
#0      RangeError.checkValidRange (dart:core/errors.dart:338:9)
#1      _StringBase.substring (dart:core-patch/string_patch.dart:400:27)
#2      _MyWidgetState.computeSecretOwn.<anonymous closure> (package:ecdhe_encrypt_playground/main.dart:382:39)
#3      new _GrowableList.generate (dart:core-patch/growable_array.dart:133:28)
#4      _MyWidgetState.computeSecretOwn (package:ecdhe_encrypt_playground/main.dart:381:12)
#5      _MyWidgetState.runYourMainDartCode (package:ecdhe_encrypt_playground/main.dart:161:36)
#6      _MyWidgetState.build.<anonymous closure> (package:ecdhe_encrypt_playground/main.dart:84:21)
#7      _InkResponseState._handleTap (package:flutter/src/material/ink_well.dart:989:21)
#8      GestureRecognizer.invokeCallback (package:flutter/src/gestures/recognizer.dart:198:24)
#9      TapGestureRecognizer.handleTapUp (package:flutter/src/gestures/tap.dart:608:11)
#10     BaseTapGestureRecognizer._checkUp (package:flutter/src/gestures/tap.dart:296:5)
#11     BaseTapGestureRecognizer.handlePrimaryPointer (package:flutter/src/gestures/tap.dart:230:7)
#12     PrimaryPointerGestureRecognizer.handleEvent (package:flutter/src/gestures/recognizer.dart:563:9)
#13     PointerRouter._dispatch (package:flutter/src/gestures/pointer_router.dart:94:12)
#14     PointerRouter._dispatchEventToRoutes.<anonymous closure> (package:flutter/src/gestures/pointer_router.dart:139:9)
#15     _LinkedHashMapMixin.forEach (dart:collection-patch/compact_hash.dart:539:8)
#16     PointerRouter._dispatchEventToRoutes (package:flutter/src/gestures/pointer_router.dart:137:18)
#17     PointerRouter.route (package:flutter/src/gestures/pointer_router.dart:123:7)
#18     GestureBinding.handleEvent (package:flutter/src/gestures/binding.dart:439:19)
#19     GestureBinding.dispatchEvent (package:flutter/src/gestures/binding.dart:419:22)
#20     RendererBinding.dispatchEvent (package:flutter/src/rendering/binding.dart:322:11)
#21     GestureBinding._handlePointerEventImmediately (package:flutter/src/gestures/binding.dart:374:7)
#22     GestureBinding.handlePointerEvent (package:flutter/src/gestures/binding.dart:338:5)
#23     GestureBinding._flushPointerEventQueue (package:flutter/src/gestures/binding.dart:296:7)
#24     GestureBinding._handlePointerDataPacket (package:flutter/src/gestures/binding.dart:279:7)
#28     _invoke1 (dart:ui/hooks.dart:169:10)
#29     PlatformDispatcher._dispatchPointerDataPacket (dart:ui/platform_dispatcher.dart:293:7)
#30     _dispatchPointerDataPacket (dart:ui/hooks.dart:88:31)
(elided 3 frames from dart:async)
Handler: "onTap"
Recognizer: TapGestureRecognizer#5482f
  debugOwner: GestureDetector
  state: possible
  won arena
  finalPosition: Offset(370.0, 899.3)
  finalLocalPosition: Offset(81.3, 15.3)
  button: 1
  sent tap down

 */

    int AES_GCM_NONCE_BYTES = 12; // AES GCM recommended nonce length = 96 bit = 12 byte

    //String programInfo = 'ECDHE encryption with Elliptic curve key exchange using curve P-256 and AES-256 in GCM mode. It works like the SEALED BOX in SODIUM.';
    String programInfo = 'ECDHE encryption with Elliptic curve key exchange using curve P-384 and AES-256 in GCM mode. It works like the SEALED BOX in SODIUM.';
    //String programInfo = 'ECDHE encryption with Elliptic curve key exchange using curve P-521 and AES-256 in GCM mode. It works like the SEALED BOX in SODIUM.';
    printC(programInfo);

    printC('\nStep 1: generate an ECDH keypair by the recipient');
    // generate a private key with curve P-256 / P-384 / P-512
    //PrivateKey privateKeyRecipient = generateEcdhKeyP256();
    PrivateKey privateKeyRecipient = generateEcdhKeyP384();
    //PrivateKey privateKeyRecipient = generateEcdhKeyP521();
    PublicKey publicKeyRecipient = privateKeyRecipient.publicKey;
    String publicKeyRecipientHex = publicKeyRecipient.toHex();

    printC('\nStep 2: send the public key to the sender');
    printC('publicKeyRecipient as hex string: ' + publicKeyRecipientHex);

    printC('\nStep 3: the sender has a message to encrypt');
    String plaintext = 'The quick brown fox jumps over the lazy dog';
    printC('plaintext: ' + plaintext);

    printC('\nStep 4: generate an Ephemeral ECDH keypair by the sender');
    //PrivateKey privateKeySenderEphemeral = generateEcdhKeyP256();
    PrivateKey privateKeySenderEphemeral = generateEcdhKeyP384();
    //PrivateKey privateKeySenderEphemeral = generateEcdhKeyP521();
    PublicKey publicKeySenderEphemeral = privateKeySenderEphemeral.publicKey;

    printC('\nStep 5: calculate the sharedSecretSender from privateKeySender and publicKeyRecipient');
    // first: rebuild the publicKey from the hexstring
    //PublicKey publicKeyRecipientFromHexstring = publicKeyFromHexstringP256(publicKeyRecipientHex);
    PublicKey publicKeyRecipientFromHexstring = publicKeyFromHexstringP384(publicKeyRecipientHex);
    //PublicKey publicKeyRecipientFromHexstring = publicKeyFromHexstringP521(publicKeyRecipientHex);
    List<int> sharedSecretSender = computeSecret(privateKeySenderEphemeral, publicKeyRecipientFromHexstring);
    //List<int> sharedSecretSender = computeSecretOwn(privateKeySenderEphemeral, publicKeyRecipientFromHexstring);
    printC('sharedSecretSender length: ' + sharedSecretSender.length.toString());
    printC('sharedSecretSender (base64): ' + base64EncodingListInt(sharedSecretSender));

    printC('\nStep 6: calculate a hash from publicKeySender and publicKeyRecipient using Blake2b algorithm');
    Uint8List nonceSender = getNonceByBlake2b(publicKeySenderEphemeral.toHex(), publicKeyRecipientHex, AES_GCM_NONCE_BYTES);
    printC('nonceSender (base64): ' + base64Encoding(nonceSender));

    printC('\nStep 7: encrypt the plaintext with algorithm AES GCM mode, use sharedSecretSender and nonceSender as parameters');
    Uint8List ciphertextSender = aesGcmEncryptToUint8List(sharedSecretSender, nonceSender, plaintext);
    printC('ciphertext (base64): ' + base64Encoding(ciphertextSender));

    printC('\nStep 8: concatenate the publicKeySender and ciphertext to a SEALED BOX');
    Uint8List sealedBox = makeASealedBox(publicKeySenderEphemeral, ciphertextSender);
    // sealedBox is publicKeySender length (4 bytes) - publicKeySender - ciphertext
    String sealedBoxBase64 = base64Encoding(sealedBox);
    printC('sealedBox base64: ' + sealedBoxBase64);

    printC('\nStep 9: send the sealed box to the recipient');
    Uint8List sealedBoxRecipient = base64Decoding(sealedBoxBase64);

    printC('\nStep 10: split the sealedBox into publicKeySender and ciphertext');
    // 1 get the bytes 0..3 and get the length of the following publicKeySender
    Uint8List publicKeySenderLengthUint8List = new Uint8List.sublistView(sealedBoxRecipient, 0, 4);

    // 2 convert the data back to int
    int publicKeySenderLength = getPublicKeyLength(publicKeySenderLengthUint8List);
    // 3 get the publicKeySender
    Uint8List publicKeySenderUint8List = new Uint8List.sublistView(sealedBoxRecipient, 4, (4 + publicKeySenderLength));
    //PublicKey publicKeySender = publicKeyFromUint8ListP256(publicKeySenderUint8List);
    PublicKey publicKeySender = publicKeyFromUint8ListP384(publicKeySenderUint8List);
    //PublicKey publicKeySender = publicKeyFromUint8ListP521(publicKeySenderUint8List);
    // 4 get the ciphertext
    Uint8List ciphertextReceived = new Uint8List.sublistView(sealedBoxRecipient, (4 + publicKeySenderLength), sealedBoxRecipient.lengthInBytes);

    printC('\nStep 11: generate the nonce from publicKeySender and publicKeyRecipient using Blake2b');
    Uint8List nonceBlake2bRecipient = getNonceByBlake2b(publicKeySender.toHex(), publicKeyRecipient.toHex(), AES_GCM_NONCE_BYTES);
    printC('nonceBlake2bRecipient base64: ' + base64.encode(nonceBlake2bRecipient));

    printC('\nStep 12: generate the sharedSecretRecipient');
    List<int> secretKeyRecipient = computeSecret(privateKeyRecipient, publicKeySender);
    //List<int> secretKeyRecipient = computeSecret(privateKeyRecipient, publicKeySender);
    printC('secretKeyRecipient length: ' + secretKeyRecipient.length.toString());
    printC('secretKeyRecipient base64: ' + base64Encoding(Uint8List.fromList(secretKeyRecipient)));

    printC('\nStep 13: decrypt the ciphertext');
    printC('ciphertextReceived base64: ' + base64Encoding(ciphertextReceived));
    String cleartext = aesGcmDecryptFromUint8List(secretKeyRecipient, nonceBlake2bRecipient, ciphertextReceived);
    printC('decryptedText: ' + cleartext);
  }

  Uint8List aesGcmEncryptToUint8List(
      List<int> key, Uint8List nonce, String plaintext) {
    print('** aesGcmEncrypt key: ' + base64Encoding(Uint8List.fromList(key)) + ' nonce: ' + base64Encoding(nonce));
    // cut the key length if longer then 32
    if (key.length > 32) {
      key = key.sublist(0, 32);
      print('key.length new: ' + key.length.toString());
    }
    try {
      var plaintextUint8 = createUint8ListFromString(plaintext);
      final cipher = pc.GCMBlockCipher(pc.AESEngine());
      var aeadParameters =
      pc.AEADParameters(pc.KeyParameter(Uint8List.fromList(key)), 128, nonce, Uint8List(0));
      cipher.init(true, aeadParameters);
      var ciphertextWithTag = cipher.process(plaintextUint8);
      return ciphertextWithTag;
    } catch (error) {
      return Uint8List(0);
    }
  }

  String aesGcmDecryptFromUint8List(List<int> key, Uint8List nonce, Uint8List ciphertext)
  {
    print('** aesGcmDecrypt key: ' + base64Encoding(Uint8List.fromList(key)) + ' nonce: ' + base64Encoding(nonce));
    // cut the key length if longer then 32
    if (key.length > 32) {
      key = key.sublist(0, 32);
      print('key.length new: ' + key.length.toString());
    }
    try {
      final cipher = pc.GCMBlockCipher(pc.AESEngine());
      var aeadParameters =
      pc.AEADParameters(pc.KeyParameter(Uint8List.fromList(key)), 128, nonce, Uint8List(0));
      cipher.init(false, aeadParameters);
      return String.fromCharCodes(cipher.process(ciphertext));
    } catch (error) {
      printC('error: ' + error.toString());
      return 'Fehler bei der Entschlüsselung';
    }
  }

  // awaits the publicKeys as hex encoded strings, returns the hashed result
  Uint8List getNonceByBlake2b(String publicKeySender, String publicKeyRecipient, int nonceBytes) {
    var dig = pc.Blake2bDigest(digestSize: nonceBytes);
    //var input = createUint8ListFromHexString(publicBob.toCompressedHex());
    var input = createUint8ListFromHexString(publicKeySender);
    printC('input = pubKey length: ' + input.lengthInBytes.toString());
    dig.update(input, 0, input.length);
    input = createUint8ListFromHexString(publicKeyRecipient);
    dig.update(input, 0, input.length);
    Uint8List nonceNew = new Uint8List(nonceBytes);
    var number = 0;
    number = dig.doFinal(nonceNew, 0);
    return nonceNew;
  }

  Uint8List generateRandomNonce() {
    final _sGen = Random.secure();
    final _seed =
    Uint8List.fromList(List.generate(32, (n) => _sGen.nextInt(255)));
    pc.SecureRandom sec = pc.SecureRandom("Fortuna")
      ..seed(pc.KeyParameter(_seed));
    return sec.nextBytes(12);
  }

  Uint8List createUint8ListFromString(String s) {
    var ret = new Uint8List(s.length);
    for (var i = 0; i < s.length; i++) {
      ret[i] = s.codeUnitAt(i);
    }
    return ret;
  }

  Uint8List createUint8ListFromHexString(String hex) {
    hex = hex.replaceAll(RegExp(r'\s'), ''); // remove all whitespace, if any

    var result = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < hex.length; i += 2) {
      var num = hex.substring(i, i + 2);
      var byte = int.parse(num, radix: 16);
      result[i ~/ 2] = byte;
    }
    return result;
  }

  //----------------------------------------------------------------
  /// Represent bytes in hexadecimal
  ///
  /// If a [separator] is provided, it is placed the hexadecimal characters
  /// representing each byte. Otherwise, all the hexadecimal characters are
  /// simply concatenated together.
  String bin2hex(Uint8List bytes, {String? separator, int? wrap}) {
    var len = 0;
    final buf = StringBuffer();
    for (final b in bytes) {
      final s = b.toRadixString(16);
      if (buf.isNotEmpty && separator != null) {
        buf.write(separator);
        len += separator.length;
      }
      if (wrap != null && wrap < len + 2) {
        buf.write('\n');
        len = 0;
      }
      buf.write('${(s.length == 1) ? '0' : ''}$s');
      len += 2;
    }
    return buf.toString();
  }

  String base64Encoding(Uint8List input) {
    return base64.encode(input);
  }

  String base64EncodingListInt(List<int> input) {
    return base64.encode(input);
  }

  Uint8List base64Decoding(String input) {
    return base64.decode(input);
  }

  void runYourSecondDartCode() {
    printC('execute additional code');
  }

  PrivateKey generateEcdhKeyP256() {
    var ec = getP256();
    return ec.generatePrivateKey();
  }

  PublicKey publicKeyFromHexstringP256(String publicKeyHex) {
    var ec = getP256();
    return ec.hexToPublicKey(publicKeyHex);
  }

  PublicKey publicKeyFromUint8ListP256(Uint8List publicKeyUint8List) {
    var ec = getP256();
    return ec.hexToPublicKey(bin2hex(publicKeyUint8List));
  }

  PrivateKey generateEcdhKeyP384() {
    var ec = getP384();
    return ec.generatePrivateKey();
  }

  PublicKey publicKeyFromHexstringP384(String publicKeyHex) {
    var ec = getP384();
    return ec.hexToPublicKey(publicKeyHex);
  }

  PublicKey publicKeyFromUint8ListP384(Uint8List publicKeyUint8List) {
    var ec = getP384();
    return ec.hexToPublicKey(bin2hex(publicKeyUint8List));
  }

  PrivateKey generateEcdhKeyP521() {
    var ec = getP521();
    return ec.generatePrivateKey();
  }

  PublicKey publicKeyFromHexstringP521(String publicKeyHex) {
    var ec = getP521();
    return ec.hexToPublicKey(publicKeyHex);
  }

  PublicKey publicKeyFromUint8ListP521(Uint8List publicKeyUint8List) {
    var ec = getP521();
    return ec.hexToPublicKey(bin2hex(publicKeyUint8List));
  }

  List<int> computeSecretOwn(PrivateKey selfPriv, PublicKey otherPub) {
    assert(selfPriv.curve == otherPub.curve);
    var curve = selfPriv.curve;
    var byteLen = (curve.bitSize + 7) ~/ 8;
    var p = curve.scalarMul(otherPub, selfPriv.bytes);
    var hex = p.X.toRadixString(16);
    return List<int>.generate(
        byteLen, (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16));
  }

  /*
  The sealedBox is a concatination of publicKeyLength (4 byte) | publicKey | ciphertext
  */
  Uint8List makeASealedBox(PublicKey publicKeySender, Uint8List ciphertext) {
    // get the publicKey as Uint8List
    Uint8List publicKeyUint8List = createUint8ListFromHexString(publicKeySender.toHex());
    // get the length, for P-256 it is 65 bytes
    int publicKeyLength = publicKeyUint8List.lengthInBytes;
    // convert the int to a hexstring of 4 characters length
    String publicKeyLengthHex = publicKeyLength.toRadixString(16).padLeft(4, '0');
    // convert the hexstring to an Uint8List
    //Uint8List publicKeyLengthUint8List = createUint8ListFromHexString(publicKeyLengthHex);
    Uint8List publicKeyLengthUint8List = createUint8ListFromString(publicKeyLengthHex);
    // concatenate the data
    var bb = BytesBuilder();
    bb.add(publicKeyLengthUint8List); // 2 bytes length of the following public key
    bb.add(createUint8ListFromHexString(publicKeySender.toHex())); // the publicKey
    bb.add(ciphertext); // the ciphertext
    return bb.toBytes();
  }

  int getPublicKeyLength(Uint8List publicKeyLengthUint8List) {
    //printC('publicKeyLengthUint8List hex: ' + bin2hex(publicKeyLengthUint8List));
    String publicKeyLengthHex = new String.fromCharCodes(publicKeyLengthUint8List);
    if (publicKeyLengthHex.length == 1) {
      publicKeyLengthHex = '0' + publicKeyLengthHex;
    }
    return int.parse(publicKeyLengthHex, radix: 16);
  }


}
