import 'dart:convert';
import 'dart:typed_data';

import 'package:crypton/crypton.dart';

void main() {
  final rsaKeypair = RSAKeypair.fromRandom();
  final message =
      utf8.encode(DateTime.now().millisecondsSinceEpoch.toRadixString(16));

  final privateKeyString = rsaKeypair.privateKey.toString();
  final publicKeyString = rsaKeypair.publicKey.toString();
  final signature =
      rsaKeypair.privateKey.createSHA256Signature(message as Uint8List);
  final verified =
      rsaKeypair.publicKey.verifySHA256Signature(message, signature);

  print('Your Private Key\n $privateKeyString\n---');
  print('Your Public Key\n $publicKeyString\n---');

  if (verified) {
    print('The Signature is verified!');
  } else {
    print('The Signature could not be verified!');
  }
}
