import 'dart:convert';
import 'dart:typed_data';

import 'package:crypton/crypton.dart';
import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/export.dart' as pointy;

class RSAPrivateKey implements PrivateKey {
  pointy.RSAPrivateKey _privateKey;
  static pointy.ECCurve_secp256k1 secp256k1 = pointy.ECCurve_secp256k1();

  RSAPrivateKey(BigInt modulus, BigInt exponent, BigInt p, BigInt q) {
    this._privateKey = pointy.RSAPrivateKey(modulus, exponent, p, q);
  }

  RSAPrivateKey.fromString(String privateKeyString) {
    List<int> privateKeyDER = base64Decode(privateKeyString);
    ASN1Parser asn1Parser = ASN1Parser(privateKeyDER);
    ASN1Sequence topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    ASN1Object privateKey = topLevelSeq.elements[2];

    asn1Parser = ASN1Parser(privateKey.contentBytes());
    ASN1Sequence pkSeq = asn1Parser.nextObject() as ASN1Sequence;

    ASN1Integer modulus = pkSeq.elements[1] as ASN1Integer;
    ASN1Integer privateExponent = pkSeq.elements[3] as ASN1Integer;
    ASN1Integer p = pkSeq.elements[4] as ASN1Integer;
    ASN1Integer q = pkSeq.elements[5] as ASN1Integer;

    this._privateKey = pointy.RSAPrivateKey(
        modulus.valueAsBigInteger,
        privateExponent.valueAsBigInteger,
        p.valueAsBigInteger,
        q.valueAsBigInteger);
  }

  @override
  String createSignature(String message) {
    pointy.Signer signer = pointy.Signer('SHA-256/RSA');
    pointy.AsymmetricKeyParameter<pointy.RSAPrivateKey> privateKeyParams =
        pointy.PrivateKeyParameter(this._privateKey);
    signer.init(true, privateKeyParams);
    pointy.RSASignature sig = signer.generateSignature(utf8.encode(message));
    return base64Encode(sig.bytes);
  }

  @override
  String decrypt(String message) {
    pointy.RSAEngine cipher = pointy.RSAEngine();
    cipher.init(false,
        pointy.PrivateKeyParameter<pointy.RSAPrivateKey>(this._privateKey));
    var text = cipher.process(base64Decode(message));
    return utf8.decode(text);
  }

  @override
  RSAPublicKey get publicKey =>
      RSAPublicKey(_privateKey.modulus, BigInt.parse('65537'));

  @override
  String toString() {
    ASN1Integer version = ASN1Integer(BigInt.from(0));

    ASN1Sequence algorithmSeq = ASN1Sequence();
    ASN1Object algorithmAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList(
        [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
    ASN1Object paramsAsn1Obj =
        ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
    algorithmSeq.add(algorithmAsn1Obj);
    algorithmSeq.add(paramsAsn1Obj);

    ASN1Sequence privateKeySeq = ASN1Sequence();
    ASN1Integer modulus = ASN1Integer(this._privateKey.n);
    ASN1Integer publicExponent = ASN1Integer(BigInt.parse('65537'));
    ASN1Integer privateExponent = ASN1Integer(this._privateKey.d);
    ASN1Integer p = ASN1Integer(this._privateKey.p);
    ASN1Integer q = ASN1Integer(this._privateKey.q);
    BigInt dP = this._privateKey.d % (this._privateKey.p - BigInt.from(1));
    ASN1Integer exp1 = ASN1Integer(dP);
    BigInt dQ = this._privateKey.d % (this._privateKey.q - BigInt.from(1));
    ASN1Integer exp2 = ASN1Integer(dQ);
    BigInt iQ = this._privateKey.q.modInverse(this._privateKey.p);
    ASN1Integer co = ASN1Integer(iQ);

    privateKeySeq.add(version);
    privateKeySeq.add(modulus);
    privateKeySeq.add(publicExponent);
    privateKeySeq.add(privateExponent);
    privateKeySeq.add(p);
    privateKeySeq.add(q);
    privateKeySeq.add(exp1);
    privateKeySeq.add(exp2);
    privateKeySeq.add(co);
    ASN1OctetString publicKeySeqOctetString =
        ASN1OctetString(Uint8List.fromList(privateKeySeq.encodedBytes));

    ASN1Sequence topLevelSeq = ASN1Sequence();
    topLevelSeq.add(version);
    topLevelSeq.add(algorithmSeq);
    topLevelSeq.add(publicKeySeqOctetString);
    return base64.encode(topLevelSeq.encodedBytes);
  }
}
