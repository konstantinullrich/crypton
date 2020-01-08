import 'dart:convert';

import 'package:crypton/crypton.dart';
import 'package:encrypt/encrypt.dart';

void main() {
  var bob = ECKeypair.fromRandom();
  var alice = ECKeypair.fromRandom();
  var message = DateTime.now().millisecondsSinceEpoch.toRadixString(16);

  var encryptionKeyBob = ECEncryptionKey(bob.privateKey, alice.publicKey);
  var encryptionKeyAlice = ECEncryptionKey(alice.privateKey, bob.publicKey);

  print('Encryption Key of Bob: ${encryptionKeyBob.toString()}\n'
      'Encryption Key of Alice: ${encryptionKeyAlice.toString()}');
  print(
      'They match: ${(encryptionKeyBob.toString() == encryptionKeyAlice.toString()).toString()}');
  print(
      'The key is ${utf8.encode(encryptionKeyBob.toString()).length} bits long');

  final encrypter =
      Encrypter(Salsa20(Key(utf8.encode(encryptionKeyBob.toString()))));
  final decrypter =
      Encrypter(Salsa20(Key(utf8.encode(encryptionKeyAlice.toString()))));
  final iv = IV.fromLength(8);

  final encrypted = encrypter.encrypt(message, iv: iv);
  final decrypted = decrypter.decrypt(encrypted, iv: iv);
  print(decrypted == message);
}
