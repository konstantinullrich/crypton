import 'dart:convert';

import 'package:crypton/crypton.dart';
import 'package:pointycastle/export.dart' as pointy;

/// [PrivateKey] using EC Algorithm
class ECPrivateKey implements PrivateKey {
  pointy.ECPrivateKey _privateKey;
  static final pointy.ECDomainParameters curve = pointy.ECCurve_secp256k1();

  /// Create an [ECPrivateKey] for the given d parameter.
  ECPrivateKey(BigInt d) {
    _privateKey = pointy.ECPrivateKey(d, curve);
  }

  /// Create an [ECPrivateKey] from the given String.
  ECPrivateKey.fromString(String privateKeyString) {
    _privateKey =
        pointy.ECPrivateKey(BigInt.parse(privateKeyString, radix: 16), curve);
  }

  /// Sign an message which can be verified using the associated [ECPublicKey]
  @override
  String createSignature(String message) {
    var privateKeyParams = pointy.PrivateKeyParameter(_privateKey);
    var signer = pointy.Signer('SHA-256/DET-ECDSA');
    signer.init(true, privateKeyParams);
    pointy.ECSignature signature =
        signer.generateSignature(utf8.encode(message));
    return signature.r.toRadixString(16) + signature.s.toRadixString(16);
  }

  /// Get the [ECPublicKey] of the [ECPrivateKey]
  @override
  ECPublicKey get publicKey {
    var Q = curve.G * _privateKey.d;
    return ECPublicKey(Q.x.toBigInteger(), Q.y.toBigInteger());
  }

  /// Get the d Parameter as [BigInt]
  BigInt get d => _privateKey.d;

  /// Export a [ECPrivateKey] as Pointy Castle ECPrivateKey
  @override
  pointy.ECPrivateKey get asPointyCastle => _privateKey;

  /// Export a [ECPrivateKey] as String which can be reversed using [ECPrivateKey.fromString].
  @override
  String toString() => _privateKey.d.toRadixString(16);
}
