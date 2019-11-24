import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:crypton/crypton.dart';
import 'package:pointycastle/export.dart' as pointy;

class RSAPublicKey implements PublicKey {
  pointy.RSAPublicKey _publicKey;

  RSAPublicKey(BigInt modulus, BigInt exponent) {
    this._publicKey = pointy.RSAPublicKey(modulus, exponent);
  }

  RSAPublicKey.fromString(String publicKeyString) {
    List<int> publicKeyDER = base64Decode(publicKeyString);
    ASN1Parser asn1Parser = ASN1Parser(publicKeyDER);
    ASN1Sequence topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    ASN1Object publicKeyBitString = topLevelSeq.elements[1];

    ASN1Parser publicKeyAsn = ASN1Parser(publicKeyBitString.contentBytes());
    ASN1Sequence publicKeySeq = publicKeyAsn.nextObject();
    ASN1Integer modulus = publicKeySeq.elements[0] as ASN1Integer;
    ASN1Integer exponent = publicKeySeq.elements[1] as ASN1Integer;

    this._publicKey = pointy.RSAPublicKey(
        modulus.valueAsBigInteger, exponent.valueAsBigInteger);
  }

  @override
  bool verifySignature(String message, String signature) {
    pointy.Signer signer = pointy.Signer('SHA-256/RSA');
    pointy.AsymmetricKeyParameter<pointy.RSAPublicKey> publicKeyParams =
        pointy.PublicKeyParameter(this._publicKey);
    pointy.RSASignature sig = pointy.RSASignature(base64Decode(signature));
    signer.init(false, publicKeyParams);
    return signer.verifySignature(utf8.encode(message), sig);
  }

  @override
  String encrypt(String message) {
    pointy.RSAEngine cipher = pointy.RSAEngine();
    cipher.init(
        true, pointy.PublicKeyParameter<pointy.RSAPublicKey>(this._publicKey));
    return base64Encode(cipher.process(utf8.encode(message)));
  }

  @override
  String toString() {
    ASN1Sequence algorithmSeq = ASN1Sequence();
    ASN1Object algorithmAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList(
        [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
    ASN1Object paramsAsn1Obj =
        ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
    algorithmSeq.add(algorithmAsn1Obj);
    algorithmSeq.add(paramsAsn1Obj);

    ASN1Sequence publicKeySeq = ASN1Sequence();
    publicKeySeq.add(ASN1Integer(this._publicKey.modulus));
    publicKeySeq.add(ASN1Integer(this._publicKey.exponent));
    ASN1BitString publicKeySeqBitString =
        ASN1BitString(Uint8List.fromList(publicKeySeq.encodedBytes));

    ASN1Sequence topLevelSeq = ASN1Sequence();
    topLevelSeq.add(algorithmSeq);
    topLevelSeq.add(publicKeySeqBitString);
    return base64.encode(topLevelSeq.encodedBytes);
  }
}
