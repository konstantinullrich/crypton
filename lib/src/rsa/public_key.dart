import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:crypton/crypton.dart';
import 'package:pointycastle/export.dart' as pointy;

/// [PublicKey] using RSA Algorithm
class RSAPublicKey implements PublicKey {
  pointy.RSAPublicKey _publicKey;

  /// Create an [RSAPublicKey] for the given parameters.
  RSAPublicKey(BigInt modulus, BigInt exponent) {
    _publicKey = pointy.RSAPublicKey(modulus, exponent);
  }

  /// Create an [RSAPublicKey] from the given String.
  RSAPublicKey.fromString(String publicKeyString) {
    List<int> publicKeyDER = base64Decode(publicKeyString);
    var asn1Parser = ASN1Parser(publicKeyDER);
    var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    var publicKeyBitString = topLevelSeq.elements[1];

    var publicKeyAsn = ASN1Parser(publicKeyBitString.contentBytes());
    ASN1Sequence publicKeySeq = publicKeyAsn.nextObject();
    var modulus = publicKeySeq.elements[0] as ASN1Integer;
    var exponent = publicKeySeq.elements[1] as ASN1Integer;

    _publicKey = pointy.RSAPublicKey(
        modulus.valueAsBigInteger, exponent.valueAsBigInteger);
  }

  // TODO: Add Documentation
  @override
  bool verifySignature(String message, String signature) {
    var signer = pointy.Signer('SHA-256/RSA');
    pointy.AsymmetricKeyParameter<pointy.RSAPublicKey> publicKeyParams =
        pointy.PublicKeyParameter(_publicKey);
    var sig = pointy.RSASignature(base64Decode(signature));
    signer.init(false, publicKeyParams);
    return signer.verifySignature(utf8.encode(message), sig);
  }

  // TODO: Add Documentation
  String encrypt(String message) {
    var cipher = pointy.RSAEngine();
    cipher.init(
        true, pointy.PublicKeyParameter<pointy.RSAPublicKey>(_publicKey));
    return base64Encode(cipher.process(utf8.encode(message)));
  }

  /// Export a [RSAPublicKey] as Pointy Castle RSAPublicKey
  @override
  pointy.RSAPublicKey get asPointyCastle => _publicKey;

  /// Export a [RSAPublic] key as String which can be reversed using [RSAPublicKey.fromString].
  @override
  String toString() {
    var algorithmSeq = ASN1Sequence();
    var algorithmAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList(
        [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
    var paramsAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
    algorithmSeq.add(algorithmAsn1Obj);
    algorithmSeq.add(paramsAsn1Obj);

    var publicKeySeq = ASN1Sequence();
    publicKeySeq.add(ASN1Integer(_publicKey.modulus));
    publicKeySeq.add(ASN1Integer(_publicKey.exponent));
    var publicKeySeqBitString =
        ASN1BitString(Uint8List.fromList(publicKeySeq.encodedBytes));

    var topLevelSeq = ASN1Sequence();
    topLevelSeq.add(algorithmSeq);
    topLevelSeq.add(publicKeySeqBitString);
    return base64.encode(topLevelSeq.encodedBytes);
  }
}
