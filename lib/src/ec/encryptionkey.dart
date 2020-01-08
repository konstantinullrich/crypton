import 'package:crypton/crypton.dart';

class ECEncryptionKey{
  final ECPrivateKey _privateKey;
  final ECPublicKey _publicKey;

  /// Use your [ECPrivateKey] and the [ECPublicKey] of your opponent to co
  ECEncryptionKey(this._privateKey, this._publicKey);

  /// Get an encryption key, which can be used for symmetric encryption
  @override
  String toString() => (_publicKey.Q * _privateKey.d).x.toString();
}