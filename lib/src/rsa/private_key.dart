import 'dart:convert';
import 'dart:typed_data';

import 'package:crypton/crypton.dart';
import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/export.dart' as pointy;

/// [PrivateKey] using RSA Algorithm
class RSAPrivateKey implements PrivateKey {
  pointy.RSAPrivateKey _privateKey;
  static pointy.ECCurve_secp256k1 secp256k1 = pointy.ECCurve_secp256k1();

  /// Create an [RSAPrivateKey] for the given parameters.
  RSAPrivateKey(BigInt modulus, BigInt exponent, BigInt p, BigInt q) {
    _privateKey = pointy.RSAPrivateKey(modulus, exponent, p, q);
  }

  /// Create an [RSAPrivateKey] from the given String.
  RSAPrivateKey.fromString(String privateKeyString) {
    List<int> privateKeyDER = base64Decode(privateKeyString);
    var asn1Parser = ASN1Parser(privateKeyDER);
    var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    var privateKey = topLevelSeq.elements[2];

    asn1Parser = ASN1Parser(privateKey.contentBytes());
    var pkSeq = asn1Parser.nextObject() as ASN1Sequence;

    var modulus = pkSeq.elements[1] as ASN1Integer;
    var privateExponent = pkSeq.elements[3] as ASN1Integer;
    var p = pkSeq.elements[4] as ASN1Integer;
    var q = pkSeq.elements[5] as ASN1Integer;

    _privateKey = pointy.RSAPrivateKey(
        modulus.valueAsBigInteger,
        privateExponent.valueAsBigInteger,
        p.valueAsBigInteger,
        q.valueAsBigInteger);
  }

  // TODO: Add Documentation
  @override
  String createSignature(String message) {
    var signer = pointy.Signer('SHA-256/RSA');
    pointy.AsymmetricKeyParameter<pointy.RSAPrivateKey> privateKeyParams =
        pointy.PrivateKeyParameter(_privateKey);
    signer.init(true, privateKeyParams);
    pointy.RSASignature sig = signer.generateSignature(utf8.encode(message));
    return base64Encode(sig.bytes);
  }

  /// Decrypt a message which was encrypted using the associated [RSAPublicKey]
  String decrypt(String message) {
    var cipher = pointy.RSAEngine();
    cipher.init(
        false, pointy.PrivateKeyParameter<pointy.RSAPrivateKey>(_privateKey));
    var text = cipher.process(base64Decode(message));
    return utf8.decode(text);
  }

  /// Get the [RSAPublicKey] of the [RSAPrivateKey]
  @override
  RSAPublicKey get publicKey =>
      RSAPublicKey(_privateKey.modulus, BigInt.parse('65537'));

  /// Export a [RSAPrivateKey] as Pointy Castle RSAPrivateKey
  @override
  pointy.RSAPrivateKey get asPointyCastle => _privateKey;

  /// Export a [RSAPrivateKey] as String which can be reversed using [RSAPrivateKey.fromString].
  @override
  String toString() {
    var version = ASN1Integer(BigInt.from(0));

    var algorithmSeq = ASN1Sequence();
    var algorithmAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList(
        [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
    var paramsAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
    algorithmSeq.add(algorithmAsn1Obj);
    algorithmSeq.add(paramsAsn1Obj);

    var privateKeySeq = ASN1Sequence();
    var modulus = ASN1Integer(_privateKey.n);
    var publicExponent = ASN1Integer(BigInt.parse('65537'));
    var privateExponent = ASN1Integer(_privateKey.d);
    var p = ASN1Integer(_privateKey.p);
    var q = ASN1Integer(_privateKey.q);
    var dP = _privateKey.d % (_privateKey.p - BigInt.from(1));
    var exp1 = ASN1Integer(dP);
    var dQ = _privateKey.d % (_privateKey.q - BigInt.from(1));
    var exp2 = ASN1Integer(dQ);
    var iQ = _privateKey.q.modInverse(_privateKey.p);
    var co = ASN1Integer(iQ);

    privateKeySeq.add(version);
    privateKeySeq.add(modulus);
    privateKeySeq.add(publicExponent);
    privateKeySeq.add(privateExponent);
    privateKeySeq.add(p);
    privateKeySeq.add(q);
    privateKeySeq.add(exp1);
    privateKeySeq.add(exp2);
    privateKeySeq.add(co);
    var publicKeySeqOctetString =
        ASN1OctetString(Uint8List.fromList(privateKeySeq.encodedBytes));

    var topLevelSeq = ASN1Sequence();
    topLevelSeq.add(version);
    topLevelSeq.add(algorithmSeq);
    topLevelSeq.add(publicKeySeqOctetString);
    return base64.encode(topLevelSeq.encodedBytes);
  }
}
