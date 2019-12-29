import 'dart:convert';

import 'package:crypton/crypton.dart';
import 'package:pointycastle/export.dart' as pointy;

/// [PublicKey] using EC Algorithm
class ECPublicKey implements PublicKey {
  pointy.ECPublicKey _publicKey;
  static final pointy.ECDomainParameters curve = pointy.ECCurve_secp256k1();

  /// Create an [ECPublicKey] for the given coordinates.
  ECPublicKey(BigInt x, BigInt y) {
    var Q = ECPoint(x, y, true);
    _publicKey = pointy.ECPublicKey(Q.asPointyCastle, curve);
  }

  /// Create an [ECPublicKey] from the given String.
  ECPublicKey.fromString(String publicKeyString) {
    var Q = curve.curve.decodePoint(base64Decode(publicKeyString));
    _publicKey = pointy.ECPublicKey(Q, curve);
  }

  /// Verify the signature of a message signed with the associated [ECPrivateKey]
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

  /// Generate a [ECIESPair] based on the [ECPublicKey]
  ECIESPair get encryptionKeypair {
    // TODO: Generate r randomly
    var r = BigInt.parse('3004200105112004');
    var R = curve.G * r;
    var S = _publicKey.Q * r;
    return ECIESPair(ECPoint(S.x.toBigInteger(), S.y.toBigInteger()),
        ECPoint(R.x.toBigInteger(), R.y.toBigInteger()));
  }

  /// Export a [ECPublicKey] as Pointy Castle ECPublicKey
  @override
  pointy.ECPublicKey get asPointyCastle => _publicKey;

  /// Export a [ECPublicKey] as String which can be reversed using [ECPublicKey.fromString].
  @override
  String toString() => base64Encode(_publicKey.Q.getEncoded());
}
