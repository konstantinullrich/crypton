import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:crypton/crypton.dart';
import 'package:pointycastle/export.dart' as pointy;

/// [PrivateKey] using RSA Algorithm
class RSAPrivateKey implements PrivateKey {
  late pointy.RSAPrivateKey _privateKey;

  /// Create an [RSAPrivateKey] for the given parameters.
  RSAPrivateKey(BigInt modulus, BigInt exponent, BigInt p, BigInt q)
      : _privateKey = pointy.RSAPrivateKey(modulus, exponent, p, q);

  /// Create an [RSAPrivateKey] from the given String.
  RSAPrivateKey.fromString(String privateKeyString) {
    List<int> privateKeyDER = base64Decode(privateKeyString);
    var asn1Parser = ASN1Parser(privateKeyDER as Uint8List);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    final privateKey = topLevelSeq.elements[2];

    asn1Parser = ASN1Parser(privateKey.contentBytes()!);
    final pkSeq = asn1Parser.nextObject() as ASN1Sequence;

    final modulus = pkSeq.elements[1] as ASN1Integer;
    final privateExponent = pkSeq.elements[3] as ASN1Integer;
    final p = pkSeq.elements[4] as ASN1Integer;
    final q = pkSeq.elements[5] as ASN1Integer;

    _privateKey = pointy.RSAPrivateKey(
        modulus.valueAsBigInteger!,
        privateExponent.valueAsBigInteger!,
        p.valueAsBigInteger,
        q.valueAsBigInteger);
  }

  /// Create an [RSAPrivateKey] from the given PEM-String.
  static RSAPrivateKey fromPEM(String pemString) {
    final rows = pemString.split(RegExp(r'\r\n?|\n'));
    final privateKeyString = rows
        .skipWhile((row) => row.startsWith('-----BEGIN'))
        .takeWhile((row) => !row.startsWith('-----END'))
        .map((row) => row.trim())
        .join('');
    return RSAPrivateKey.fromString(privateKeyString);
  }

  /// Sign an message with SHA-256 which can be verified using the associated [RSAPublicKey]
  @override
  @Deprecated('Use createSHA256Signature for creating SHA-256 signatures')
  String createSignature(String message) =>
      base64.encode(createSHA256Signature(utf8.encode(message) as Uint8List));

  /// Sign an message with SHA-256 which can be verified using the associated [RSAPublicKey]
  @override
  Uint8List createSHA256Signature(Uint8List message) =>
      _createSignature(message, 'SHA-256/RSA');

  /// Sign an message with SHA-512 which can be verified using the associated [RSAPublicKey]
  @override
  Uint8List createSHA512Signature(Uint8List message) =>
      _createSignature(message, 'SHA-512/RSA');

  Uint8List _createSignature(Uint8List message, String algorithm) {
    final signer = pointy.Signer(algorithm);
    pointy.AsymmetricKeyParameter<pointy.RSAPrivateKey> privateKeyParams =
        pointy.PrivateKeyParameter(_privateKey);
    signer.init(true, privateKeyParams);
    final sig = signer.generateSignature(message) as pointy.RSASignature;
    return sig.bytes;
  }

  /// Decrypt a message which was encrypted using the associated [RSAPublicKey]
  String decrypt(String message) =>
      utf8.decode(decryptData(base64.decode(message)));

  /// Decrypt a message which was encrypted using the associated [RSAPublicKey]
  Uint8List decryptData(Uint8List message) {
    final cipher = pointy.PKCS1Encoding(pointy.RSAEngine());
    cipher.init(
        false, pointy.PrivateKeyParameter<pointy.RSAPrivateKey>(_privateKey));
    return _processInBlocks(cipher, message);
  }

  Uint8List _processInBlocks(
      pointy.AsymmetricBlockCipher engine, Uint8List input) {
    final numBlocks = input.length ~/ engine.inputBlockSize +
        ((input.length % engine.inputBlockSize != 0) ? 1 : 0);

    final output = Uint8List(numBlocks * engine.outputBlockSize);

    var inputOffset = 0;
    var outputOffset = 0;
    while (inputOffset < input.length) {
      final chunkSize = (inputOffset + engine.inputBlockSize <= input.length)
          ? engine.inputBlockSize
          : input.length - inputOffset;

      outputOffset += engine.processBlock(
          input, inputOffset, chunkSize, output, outputOffset);

      inputOffset += chunkSize;
    }

    return (output.length == outputOffset)
        ? output
        : output.sublist(0, outputOffset);
  }

  /// Get the [RSAPublicKey] of the [RSAPrivateKey]
  @override
  RSAPublicKey get publicKey =>
      RSAPublicKey(_privateKey.modulus!, BigInt.parse('65537'));

  /// Export a [RSAPrivateKey] as Pointy Castle RSAPrivateKey
  @override
  pointy.RSAPrivateKey get asPointyCastle => _privateKey;

  /// Export a [RSAPrivateKey] as String which can be reversed using [RSAPrivateKey.fromString].
  @override
  String toString() {
    final version = ASN1Integer(BigInt.from(0));

    final algorithmSeq = ASN1Sequence();
    final algorithmAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList(
        [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
    final paramsAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
    algorithmSeq.add(algorithmAsn1Obj);
    algorithmSeq.add(paramsAsn1Obj);

    final privateKeySeq = ASN1Sequence();
    final modulus = ASN1Integer(_privateKey.n!);
    final publicExponent = ASN1Integer(BigInt.parse('65537'));
    final privateExponent = ASN1Integer(_privateKey.privateExponent!);
    final p = ASN1Integer(_privateKey.p!);
    final q = ASN1Integer(_privateKey.q!);
    final dP = _privateKey.privateExponent! % (_privateKey.p! - BigInt.from(1));
    final exp1 = ASN1Integer(dP);
    final dQ = _privateKey.privateExponent! % (_privateKey.q! - BigInt.from(1));
    final exp2 = ASN1Integer(dQ);
    final iQ = _privateKey.q!.modInverse(_privateKey.p!);
    final co = ASN1Integer(iQ);

    privateKeySeq.add(version);
    privateKeySeq.add(modulus);
    privateKeySeq.add(publicExponent);
    privateKeySeq.add(privateExponent);
    privateKeySeq.add(p);
    privateKeySeq.add(q);
    privateKeySeq.add(exp1);
    privateKeySeq.add(exp2);
    privateKeySeq.add(co);
    final publicKeySeqOctetString =
        ASN1OctetString(Uint8List.fromList(privateKeySeq.encodedBytes));

    final topLevelSeq = ASN1Sequence();
    topLevelSeq.add(version);
    topLevelSeq.add(algorithmSeq);
    topLevelSeq.add(publicKeySeqOctetString);
    return base64.encode(topLevelSeq.encodedBytes);
  }

  /// Export a [RSAPrivateKey] as PEM String which can be reversed using [RSAPrivateKey.fromPEM].
  String toPEM() {
    return '-----BEGIN RSA PRIVATE KEY-----\n${toString()}\n-----END RSA PRIVATE KEY-----';
  }

  /// Export a [RSAPrivateKey] as formatted PEM String which can be reversed using [RSAPrivateKey.fromPEM].
  String toFormattedPEM() {
    final base = toString();
    var formatted = '';
    for (var i = 0; i < base.length; i++) {
      if (i % 64 == 0 && i != 0) {
        formatted += '\n';
      }
      formatted += base[i];
    }
    return '-----BEGIN RSA PRIVATE KEY-----\n$formatted\n-----END RSA PRIVATE KEY-----';
  }
}
