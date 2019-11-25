import 'dart:convert';

import 'package:crypton/crypton.dart';
import 'package:pointycastle/export.dart' as pointy;

/// [PrivateKey] using EC Algorithm
class ECPrivateKey implements PrivateKey {
  pointy.ECPrivateKey _privateKey;
  static pointy.ECCurve_secp256k1 secp256k1 = pointy.ECCurve_secp256k1();

  /// Create an [ECPrivateKey] for the given parameters.
  ECPrivateKey(BigInt d) {
    this._privateKey = pointy.ECPrivateKey(d, secp256k1);
  }

  /// Create an [ECPrivateKey] from the given String.
  ECPrivateKey.fromString(String privateKeyString) {
    this._privateKey = pointy.ECPrivateKey(
        BigInt.parse(privateKeyString, radix: 16), secp256k1);
  }

  @override
  String createSignature(String message) {
    pointy.PrivateKeyParameter privateKeyParams =
        pointy.PrivateKeyParameter(this._privateKey);
    pointy.Signer signer = pointy.Signer("SHA-256/DET-ECDSA");
    signer.init(true, privateKeyParams);
    pointy.ECSignature signature =
        signer.generateSignature(utf8.encode(message));
    return signature.r.toRadixString(16) + signature.s.toRadixString(16);
  }

  /// Get the [ECPublicKey] of the [ECPrivateKey]
  @override
  ECPublicKey get publicKey {
    pointy.ECPoint Q = secp256k1.G * this._privateKey.d;
    return ECPublicKey(Q.x.toBigInteger(), Q.y.toBigInteger());
  }

  /// Export a [ECPrivateKey] as String which can be reversed using [ECPrivateKey.fromString].
  @override
  String toString() => this._privateKey.d.toRadixString(16);
}
