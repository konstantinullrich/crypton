import 'dart:convert';

import 'package:crypton/crypton.dart';
import 'package:pointycastle/export.dart' as pointy;

/// [PublicKey] using EC Algorithm
class ECPublicKey implements PublicKey {
  pointy.ECPublicKey _publicKey;
  static pointy.ECCurve_secp256k1 secp256k1 = pointy.ECCurve_secp256k1();

  /// Create an [ECPublicKey] for the given coordinates.
  ECPublicKey(BigInt x, BigInt y) {
    pointy.ECCurve c = secp256k1.curve;
    pointy.ECPoint Q = c.createPoint(x, y, true);
    this._publicKey = pointy.ECPublicKey(Q, secp256k1);
  }

  /// Create an [ECPublicKey] from the given String.
  ECPublicKey.fromString(String publicKeyString) {
    pointy.ECPoint Q =
        secp256k1.curve.decodePoint(base64Decode(publicKeyString));
    this._publicKey = pointy.ECPublicKey(Q, secp256k1);
  }

  @override
  bool verifySignature(String message, String signatureString) {
    int sigLength = (signatureString.length / 2).round();
    BigInt r = BigInt.parse(signatureString.substring(0, sigLength), radix: 16);
    BigInt s = BigInt.parse(signatureString.substring(sigLength), radix: 16);
    pointy.ECSignature signature = pointy.ECSignature(r, s);
    pointy.Signer signer = pointy.Signer("SHA-256/DET-ECDSA");
    signer.init(false, pointy.PublicKeyParameter(this._publicKey));
    return signer.verifySignature(utf8.encode(message), signature);
  }

  /// Export a [ECPublicKey] as String which can be reversed using [ECPublicKey.fromString].
  @override
  String toString() => base64Encode(this._publicKey.Q.getEncoded());
}
