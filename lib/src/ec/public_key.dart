import 'dart:convert';
import 'dart:typed_data';

import 'package:crypton/crypton.dart';
import 'package:pointycastle/export.dart' as pointy;

/// [PublicKey] using EC Algorithm
class ECPublicKey implements PublicKey {
  final pointy.ECPublicKey _publicKey;
  static final pointy.ECDomainParameters curve = pointy.ECCurve_secp256k1();

  /// Create an [ECPublicKey] for the given coordinates.
  ECPublicKey(BigInt x, BigInt y)
      : _publicKey =
            pointy.ECPublicKey(ECPoint(x, y, true).asPointyCastle, curve);

  /// Create an [ECPublicKey] from the given String.
  ECPublicKey.fromString(String publicKeyString)
      : _publicKey = pointy.ECPublicKey(
            curve.curve.decodePoint(base64Decode(publicKeyString)), curve);

  /// Verify the signature of a SHA256-hashed message signed with the associated [ECPrivateKey]
  @Deprecated('For SHA256 signature verification use verifySHA256Signature')
  @override
  bool verifySignature(String message, String signature) =>
      verifySHA256Signature(utf8.encode(message) as Uint8List,
          utf8.encode(signature) as Uint8List);

  /// Verify the signature of a SHA256-hashed message signed with the associated [ECPrivateKey]
  @override
  bool verifySHA256Signature(Uint8List message, Uint8List signature) =>
      _verifySignature(message, signature, 'SHA-256/DET-ECDSA');

  /// Verify the signature of a SHA512-hashed message signed with the associated [ECPrivateKey]
  @override
  bool verifySHA512Signature(Uint8List message, Uint8List signature) =>
      _verifySignature(message, signature, 'SHA-512/DET-ECDSA');

  bool _verifySignature(
      Uint8List message, Uint8List signatureString, String algorithm) {
    final sigLength = (signatureString.length / 2).round();
    final r = BigInt.parse(
      utf8.decode(signatureString.sublist(0, sigLength)),
      radix: 16,
    );
    final s = BigInt.parse(
      utf8.decode(signatureString.sublist(sigLength)),
      radix: 16,
    );
    final signature = pointy.ECSignature(r, s);
    final signer = pointy.Signer(algorithm);
    signer.init(false, pointy.PublicKeyParameter(_publicKey));
    return signer.verifySignature(message, signature);
  }

  /// Get [ECPoint] Q, which is the Public Point
  ECPoint get Q => ECPoint(_publicKey.Q!.x!.toBigInteger()!,
      _publicKey.Q!.y!.toBigInteger()!, _publicKey.Q!.isCompressed);

  /// Export a [ECPublicKey] as Pointy Castle ECPublicKey
  @override
  pointy.ECPublicKey get asPointyCastle => _publicKey;

  /// Export a [ECPublicKey] as String which can be reversed using [ECPublicKey.fromString].
  @override
  String toString() => base64Encode(_publicKey.Q!.getEncoded());
}
