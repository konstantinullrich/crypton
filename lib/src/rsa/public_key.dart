import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:crypton/crypton.dart';
import 'package:pointycastle/export.dart' as pointy;

/// [PublicKey] using RSA Algorithm
class RSAPublicKey implements PublicKey {
  late pointy.RSAPublicKey _publicKey;

  /// Create an [RSAPublicKey] for the given parameters.
  RSAPublicKey(BigInt modulus, BigInt exponent)
      : _publicKey = pointy.RSAPublicKey(modulus, exponent);

  /// Create an [RSAPublicKey] from the given String.
  RSAPublicKey.fromString(String publicKeyString) {
    List<int> publicKeyDER = base64Decode(publicKeyString);
    final asn1Parser = ASN1Parser(publicKeyDER as Uint8List);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    final publicKeyBitString = topLevelSeq.elements[1];

    final publicKeyAsn = ASN1Parser(publicKeyBitString.contentBytes()!);
    final publicKeySeq = publicKeyAsn.nextObject() as ASN1Sequence;
    final modulus = publicKeySeq.elements[0] as ASN1Integer;
    final exponent = publicKeySeq.elements[1] as ASN1Integer;

    _publicKey = pointy.RSAPublicKey(
        modulus.valueAsBigInteger!, exponent.valueAsBigInteger!);
  }

  /// Create an [RSAPublicKey] from the given PEM-String.
  static RSAPublicKey fromPEM(String pemString) {
    final rows = pemString.split(RegExp(r'\r\n?|\n'));
    final privateKeyString = rows
        .skipWhile((row) => row.startsWith('-----BEGIN'))
        .takeWhile((row) => !row.startsWith('-----END'))
        .map((row) => row.trim())
        .join('');
    return RSAPublicKey.fromString(privateKeyString);
  }

  /// Verify the signature of a SHA256-hashed message signed with the associated [RSAPrivateKey]
  @Deprecated('For SHA256 signature verification use verifySHA256Signature')
  @override
  bool verifySignature(String message, String signature) =>
      verifySHA256Signature(
          utf8.encode(message) as Uint8List, base64.decode(signature));

  /// Verify the signature of a SHA256-hashed message signed with the associated [RSAPrivateKey]
  @override
  bool verifySHA256Signature(Uint8List message, Uint8List signature) =>
      _verifySignature(message, signature, 'SHA-256/RSA');

  /// Verify the signature of a SHA512-hashed message signed with the associated [RSAPrivateKey]
  @override
  bool verifySHA512Signature(Uint8List message, Uint8List signature) =>
      _verifySignature(message, signature, 'SHA-512/RSA');

  bool _verifySignature(
      Uint8List message, Uint8List signature, String algorithm) {
    final signer = pointy.Signer(algorithm);
    pointy.AsymmetricKeyParameter<pointy.RSAPublicKey> publicKeyParams =
        pointy.PublicKeyParameter(_publicKey);
    final sig = pointy.RSASignature(signature);
    signer.init(false, publicKeyParams);
    return signer.verifySignature(message, sig);
  }

  /// Encrypt a message which can only be decrypted using the associated [RSAPrivateKey]
  String encrypt(String message) =>
      base64.encode(encryptData(utf8.encode(message) as Uint8List));

  /// Encrypt a message which can only be decrypted using the associated [RSAPrivateKey]
  Uint8List encryptData(Uint8List message) {
    final cipher = pointy.PKCS1Encoding(pointy.RSAEngine());
    cipher.init(
        true, pointy.PublicKeyParameter<pointy.RSAPublicKey>(_publicKey));
    return cipher.process(message);
  }

  /// Export a [RSAPublicKey] as Pointy Castle RSAPublicKey
  @override
  pointy.RSAPublicKey get asPointyCastle => _publicKey;

  /// Export a [RSAPublic] key as String which can be reversed using [RSAPublicKey.fromString].
  @override
  String toString() {
    final algorithmSeq = ASN1Sequence();
    final algorithmAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList(
        [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
    final paramsAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
    algorithmSeq.add(algorithmAsn1Obj);
    algorithmSeq.add(paramsAsn1Obj);

    final publicKeySeq = ASN1Sequence();
    publicKeySeq.add(ASN1Integer(_publicKey.modulus!));
    publicKeySeq.add(ASN1Integer(_publicKey.exponent!));
    final publicKeySeqBitString =
        ASN1BitString(Uint8List.fromList(publicKeySeq.encodedBytes));

    final topLevelSeq = ASN1Sequence();
    topLevelSeq.add(algorithmSeq);
    topLevelSeq.add(publicKeySeqBitString);
    return base64.encode(topLevelSeq.encodedBytes);
  }

  /// Export a [RSAPublicKey] as PEM String which can be reversed using [RSAPublicKey.fromPEM].
  String toPEM() {
    return '-----BEGIN PUBLIC KEY-----\n${toString()}\n-----END PUBLIC KEY-----';
  }

  /// Export a [RSAPublicKey] as formatted PEM String which can be reversed using [RSAPublicKey.fromPEM].
  String toFormattedPEM() {
    final base = toString();
    var formatted = '';
    for (var i = 0; i < base.length; i++) {
      if (i % 64 == 0 && i != 0) {
        formatted += '\n';
      }
      formatted += base[i];
    }
    return '-----BEGIN PUBLIC KEY-----\n$formatted\n-----END PUBLIC KEY-----';
  }
}
