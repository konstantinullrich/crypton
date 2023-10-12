import 'dart:convert';

import 'package:crypton/crypton.dart';

void main() {
  final ecKeypair = ECKeypair.fromRandom();
  final message =
      utf8.encode(DateTime.now().millisecondsSinceEpoch.toRadixString(16));

  final privateKeyString = ecKeypair.privateKey.toString();
  final publicKeyString = ecKeypair.publicKey.toString();
  final signature = ecKeypair.privateKey.createSHA256Signature(message);
  final verified =
      ecKeypair.privateKey.publicKey.verifySHA256Signature(message, signature);

  print('Your Private Key\n $privateKeyString\n---');
  print('Your Public Key\n $publicKeyString\n---');

  if (verified) {
    print('The Signature is verified!');
  } else {
    print('The Signature could not be verified!');
  }
}
