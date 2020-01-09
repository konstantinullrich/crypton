import 'dart:convert';

import 'package:crypton/crypton.dart';
import 'package:crypto/crypto.dart' as crypto;
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

  // TODO: Add Documentation
  @override
  String createSignature(String message) {
    var privateKeyParams = pointy.PrivateKeyParameter(_privateKey);
    var signer = pointy.Signer('SHA-256/DET-ECDSA');
    signer.init(true, privateKeyParams);
    pointy.ECSignature signature =
        signer.generateSignature(utf8.encode(message));
    return signature.r.toRadixString(16) + signature.s.toRadixString(16);
  }

  /// Get the decryption key based of the [ECPoint] R
  String getDecryptionKey(ECPoint R) {
    var S = R * _privateKey.d;
    var digest = crypto.sha256.convert(utf8.encode(S.x.toString()));
    return digest.toString();
  }

  /// Get the [ECPublicKey] of the [ECPrivateKey]
  @override
  ECPublicKey get publicKey {
    var Q = curve.G * _privateKey.d;
    return ECPublicKey(Q.x.toBigInteger(), Q.y.toBigInteger());
  }

  /// Export a [ECPrivateKey] as Pointy Castle ECPrivateKey
  @override
  pointy.ECPrivateKey get asPointyCastle => _privateKey;

  /// Export a [ECPrivateKey] as String which can be reversed using [ECPrivateKey.fromString].
  @override
  String toString() => _privateKey.d.toRadixString(16);
}
