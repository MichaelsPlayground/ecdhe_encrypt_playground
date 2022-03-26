import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart';
import 'package:elliptic/src/curves.dart';

void main() {
  print('test curve P521');
  var privA = generateEcdhKeyP521();
  var pubA = privA.publicKey;
  var privB = generateEcdhKeyP521();
  var sharedSecret = computeSecretHex(privB, pubA);
  print('sharedSecret: ' + sharedSecret);
}

PrivateKey generateEcdhKeyP521() {
  var ec = getP521();
  return ec.generatePrivateKey();
}

/*
gives an
Unhandled exception:
RangeError (end): Invalid value: Only valid value is 130: 132
#0      RangeError.checkValidRange (dart:core/errors.dart:338:9)
#1      _StringBase.substring (dart:core-patch/string_patch.dart:400:27)
#2      computeSecret.<anonymous closure> (package:elliptic/src/ecdh.dart:12:37)
#3      new _GrowableList.generate (dart:core-patch/growable_array.dart:133:28)
#4      computeSecret (package:elliptic/src/ecdh.dart:11:10)
#5      computeSecretHex (package:elliptic/src/ecdh.dart:16:13)
#6      main (package:ecdhe_encrypt_playground/testP521.dart:10:22)
#7      _delayEntrypointInvocation.<anonymous closure> (dart:isolate-patch/isolate_patch.dart:297:19)
 */