import 'package:crypton/crypton.dart';

class ECEncryptionPair {
  final ECPrivateKey _privateKey;
  final ECPublicKey _publicKey;

  ECEncryptionPair(this._privateKey, this._publicKey);

  String get encryptionKey {
    var newPoint = _publicKey.asPointyCastle.Q * _privateKey.asPointyCastle.d;
    return newPoint.x.toString();
  }
}