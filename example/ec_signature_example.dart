import 'dart:convert';
import 'dart:typed_data';

import 'package:crypton/crypton.dart';

void main() {
  var ecKeypair = ECKeypair.fromRandom();
  var message =
      utf8.encode(DateTime.now().millisecondsSinceEpoch.toRadixString(16));

  var privateKeyString = ecKeypair.privateKey.toString();
  var publicKeyString = ecKeypair.publicKey.toString();
  var signature =
      ecKeypair.privateKey.createSHA256Signature(message as Uint8List);
  var verified =
      ecKeypair.privateKey.publicKey.verifySHA256Signature(message, signature);

  print('Your Private Key\n $privateKeyString\n---');
  print('Your Public Key\n $publicKeyString\n---');

  if (verified) {
    print('The Signature is verified!');
  } else {
    print('The Signature could not be verified!');
  }
}
