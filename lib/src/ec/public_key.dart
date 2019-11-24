import 'dart:convert';

import 'package:crypton/crypton.dart';
import 'package:pointycastle/export.dart' as pointy;

class ECPublicKey implements PublicKey {
  pointy.ECPublicKey _publicKey;
  static pointy.ECCurve_secp256k1 secp256k1 = pointy.ECCurve_secp256k1();

  ECPublicKey(BigInt x, BigInt y) {
    pointy.ECCurve c = secp256k1.curve;
    pointy.ECPoint Q = c.createPoint(x, y, true);
    this._publicKey = pointy.ECPublicKey(Q, secp256k1);
  }

  ECPublicKey.fromString(String publicKeyString) {
    pointy.ECPoint Q = secp256k1.curve.decodePoint(base64Decode(publicKeyString));
    this._publicKey = pointy.ECPublicKey(Q, secp256k1);
  }

  @override
  String toString() => base64Encode(this._publicKey.Q.getEncoded());

  @override
  String encrypt(String message) {
    // TODO: implement encrypt
    return null;
  }

  @override
  bool verifySignature(String message, String signature) {
    // TODO: implement verifySignature
    return null;
  }
}