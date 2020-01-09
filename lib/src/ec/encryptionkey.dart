import 'dart:convert';

import 'package:crypton/crypton.dart';
import 'package:crypto/crypto.dart' as crypto;

class ECEncryptionKey {
  final ECPrivateKey _privateKey;
  final ECPublicKey _publicKey;

  /// Use your [ECPrivateKey] and the [ECPublicKey] of your opponent to co
  ECEncryptionKey(this._privateKey, this._publicKey);

  /// Get an encryption key, which can be used for symmetric encryption
  @override
  String toString() {
    var rawKey = (_publicKey.Q * _privateKey.d).x;
    var digest = crypto.sha256.convert(utf8.encode(rawKey.toString()));
    return digest.toString();
  }
}
