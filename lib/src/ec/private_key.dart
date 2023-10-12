import 'dart:convert';
import 'dart:typed_data';

import 'package:crypton/crypton.dart';
import 'package:pointycastle/export.dart' as pointy;

/// [PrivateKey] using EC Algorithm
class ECPrivateKey implements PrivateKey {
  final pointy.ECPrivateKey _privateKey;
  static final pointy.ECDomainParameters curve = pointy.ECCurve_secp256k1();

  /// Create an [ECPrivateKey] for the given d parameter.
  ECPrivateKey(BigInt d) : _privateKey = pointy.ECPrivateKey(d, curve);

  /// Create an [ECPrivateKey] from the given String.
  ECPrivateKey.fromString(String privateKeyString)
      : _privateKey = pointy.ECPrivateKey(
            BigInt.parse(privateKeyString, radix: 16), curve);

  /// Sign an message with SHA-256 which can be verified using the associated [ECPublicKey]
  @override
  @Deprecated('Use createSHA256Signature for creating SHA-256 signatures')
  String createSignature(String message) =>
      utf8.decode(createSHA256Signature(utf8.encode(message)));

  /// Sign an message with SHA-256 which can be verified using the associated [ECPublicKey]
  @override
  Uint8List createSHA256Signature(Uint8List message) =>
      _createSignature(message, 'SHA-256/DET-ECDSA');

  /// Sign an message with SHA-512 which can be verified using the associated [ECPublicKey]
  @override
  Uint8List createSHA512Signature(Uint8List message) =>
      _createSignature(message, 'SHA-512/DET-ECDSA');

  Uint8List _createSignature(Uint8List message, String algorithm) {
    final signer = pointy.Signer(algorithm);
    pointy.AsymmetricKeyParameter<pointy.ECPrivateKey> privateKeyParams =
        pointy.PrivateKeyParameter(_privateKey);
    signer.init(true, privateKeyParams);
    final sig = signer.generateSignature(message) as pointy.ECSignature;
    return utf8.encode(sig.r.toRadixString(16) + sig.s.toRadixString(16));
  }

  /// Get the [ECPublicKey] of the [ECPrivateKey]
  @override
  ECPublicKey get publicKey {
    final Q = (curve.G * d)!;
    return ECPublicKey(Q.x!.toBigInteger()!, Q.y!.toBigInteger()!);
  }

  /// Get the d Parameter as [BigInt]
  BigInt get d => _privateKey.d!;

  /// Export a [ECPrivateKey] as Pointy Castle ECPrivateKey
  @override
  pointy.ECPrivateKey get asPointyCastle => _privateKey;

  /// Export a [ECPrivateKey] as String which can be reversed using [ECPrivateKey.fromString].
  @override
  String toString() => d.toRadixString(16);
}
