import 'dart:convert';

import 'package:crypton/crypton.dart';
import 'package:encrypt/encrypt.dart';

void main() {
  var ecKeypair = ECKeypair.fromRandom();
  var message = DateTime.now().millisecondsSinceEpoch.toRadixString(16);

  var encryptionKeypair = ecKeypair.publicKey.encryptionKeypair;
 var encryptionKeyFromR =
      ecKeypair.privateKey.getDecryptionKey(encryptionKeypair.R);

  print('Encryption Key from Public Key: ${encryptionKeypair.encryptionKey}\n'
      'Encryption Key from Private Key and R: ${encryptionKeyFromR}');
  print(
      'They match: ${(encryptionKeypair.encryptionKey == encryptionKeyFromR).toString()}');
  print(
      'The key is ${utf8.encode(encryptionKeypair.encryptionKey).length} bits long');

  final encrypter =
      Encrypter(Salsa20(Key(utf8.encode(encryptionKeypair.encryptionKey))));
  final decrypter = Encrypter(Salsa20(Key(utf8.encode(encryptionKeyFromR))));
  final iv = IV.fromLength(8);

  final encrypted = encrypter.encrypt(message, iv: iv);
  final decrypted = decrypter.decrypt(encrypted, iv: iv);
  print(decrypted == message);
}
