import 'package:crypton/crypton.dart';

class ECIESPair {
  final ECPoint _S;
  final ECPoint _R;

  /// Create a [ECIESPair] with [ECPoint]s S and R
  ECIESPair(this._S, this._R);

  /// In order to encrypt your data you need the [ECPrivateKey] and this [ECPoint]
  ECPoint get R => _R;

  /// Use this Key and an symmetric cipher of your choice to encrypt your data
  String get encryptionKey => _S.x.toString();
}