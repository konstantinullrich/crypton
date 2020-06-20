import 'dart:convert';

import 'package:crypton/crypton.dart';

void main() {
  var rsaKeypair = RSAKeypair.fromRandom();
  var message =
      utf8.encode(DateTime.now().millisecondsSinceEpoch.toRadixString(16));

  var privateKeyString = rsaKeypair.privateKey.toString();
  var publicKeyString = rsaKeypair.publicKey.toString();
  var signature = rsaKeypair.privateKey.createSHA256Signature(message);
  var verified = rsaKeypair.publicKey.verifySHA256Signature(message, signature);

  print('Your Private Key\n $privateKeyString\n---');
  print('Your Public Key\n $publicKeyString\n---');

  if (verified) {
    print('The Signature is verified!');
  } else {
    print('The Signature could not be verified!');
  }
}
