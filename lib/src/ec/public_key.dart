import 'dart:convert';

import 'package:crypton/crypton.dart';
import 'package:pointycastle/export.dart' as pointy;

/// [PublicKey] using EC Algorithm
class ECPublicKey implements PublicKey {
  pointy.ECPublicKey _publicKey;
  static pointy.ECCurve_secp256k1 secp256k1 = pointy.ECCurve_secp256k1();

  /// Create an [ECPublicKey] for the given coordinates.
  ECPublicKey(BigInt x, BigInt y) {
    var c = secp256k1.curve;
    var Q = c.createPoint(x, y, true);
    _publicKey = pointy.ECPublicKey(Q, secp256k1);
  }

  /// Create an [ECPublicKey] from the given String.
  ECPublicKey.fromString(String publicKeyString) {
    var Q = secp256k1.curve.decodePoint(base64Decode(publicKeyString));
    _publicKey = pointy.ECPublicKey(Q, secp256k1);
  }

  @override
  bool verifySignature(String message, String signatureString) {
    var sigLength = (signatureString.length / 2).round();
    var r = BigInt.parse(signatureString.substring(0, sigLength), radix: 16);
    var s = BigInt.parse(signatureString.substring(sigLength), radix: 16);
    var signature = pointy.ECSignature(r, s);
    var signer = pointy.Signer('SHA-256/DET-ECDSA');
    signer.init(false, pointy.PublicKeyParameter(_publicKey));
    return signer.verifySignature(utf8.encode(message), signature);
  }

  /// Export a [ECPublicKey] as String which can be reversed using [ECPublicKey.fromString].
  @override
  String toString() => base64Encode(_publicKey.Q.getEncoded());

  /// Export a [ECPublicKey] as Pointy Castle ECPublicKey
  @override
  pointy.ECPublicKey get asPointyCastle => _publicKey;
}
