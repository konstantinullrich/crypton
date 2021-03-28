import 'dart:convert';
import 'dart:typed_data';

import 'package:crypton/crypton.dart';
import 'package:test/test.dart';

void main() {
  group('A group of RSA Key Tests', () {
    late RSAKeypair rsaKeypair;
    late Uint8List message;

    setUp(() {
      rsaKeypair = RSAKeypair.fromRandom(keySize: 2048);
      message = utf8.encode('Crypton Test Message') as Uint8List;
    });

    test('Private Key to String and back', () {
      final privateKeyString = rsaKeypair.privateKey.toString();
      final privateKey = RSAPrivateKey.fromString(privateKeyString);
      expect(privateKey.toString(), privateKeyString);
    });

    test('Public Key to string and back', () {
      final publicKeyString = rsaKeypair.publicKey.toString();
      final publicKey = RSAPublicKey.fromString(publicKeyString);
      expect(publicKey.toString(), publicKeyString);
    });

    test('Get Public Key from Privat Key', () {
      final publicKeyString = rsaKeypair.privateKey.publicKey.toString();
      expect(publicKeyString, rsaKeypair.publicKey.toString());
    });

    test('Get Public Key from PEM-String', () {
      final publicKeyString = rsaKeypair.publicKey.toString();
      final publicKey = RSAPublicKey.fromPEM(rsaKeypair.publicKey.toPEM());
      expect(publicKey.toString(), publicKeyString);
    });

    test('Get Private Key from PEM-String', () {
      final privateKeyString = rsaKeypair.privateKey.toString();
      final privateKey = RSAPrivateKey.fromPEM(rsaKeypair.privateKey.toPEM());
      expect(privateKey.toString(), privateKeyString);
    });

    test('Sign and Verify deprecated', () {
      final signature =
          // ignore: deprecated_member_use_from_same_package
          rsaKeypair.privateKey.createSignature(utf8.decode(message));
      final verified =
          // ignore: deprecated_member_use_from_same_package
          rsaKeypair.publicKey.verifySignature(utf8.decode(message), signature);
      expect(verified, isTrue);
    });

    test('Sign and Verify SHA-256', () {
      final signature = rsaKeypair.privateKey.createSHA256Signature(message);
      final verified =
          rsaKeypair.publicKey.verifySHA256Signature(message, signature);
      expect(verified, isTrue);
    });
    test('Sign and Verify SHA-512', () {
      final signature = rsaKeypair.privateKey.createSHA512Signature(message);
      final verified =
          rsaKeypair.publicKey.verifySHA512Signature(message, signature);
      expect(verified, isTrue);
    });

    test('Encrypt and Decrypt data', () {
      final encrypted = rsaKeypair.publicKey.encryptData(message);
      final decrypted = rsaKeypair.privateKey.decryptData(encrypted);
      expect(decrypted, message);
    });

    test('Encrypt and Decrypt string', () {
      final encrypted = rsaKeypair.publicKey.encrypt(utf8.decode(message));
      final decrypted = utf8.encode(rsaKeypair.privateKey.decrypt(encrypted));
      expect(decrypted, message);
    });

    test('Private key PEM-String is formatted', () {
      expect(
          (rsaKeypair.privateKey
                  .toFormattedPEM()
                  .split('\n')
                  .map((l) => l.length)
                  .toList()
                    ..sort())
              .last,
          64);
    });

    test('Public key PEM-String is formatted', () {
      expect(
          (rsaKeypair.publicKey
                  .toFormattedPEM()
                  .split('\n')
                  .map((l) => l.length)
                  .toList()
                    ..sort())
              .last,
          64);
      expect(rsaKeypair.publicKey.toFormattedPEM().length, 450);
    });
  });

  group('A group of EC Key Tests', () {
    late ECKeypair ecKeypair;
    late Uint8List message;

    setUp(() {
      ecKeypair = ECKeypair.fromRandom();
      message =
          utf8.encode(DateTime.now().millisecondsSinceEpoch.toRadixString(16))
              as Uint8List;
    });

    test('Private Key to String and back', () {
      final privateKeyString = ecKeypair.privateKey.toString();
      final privateKey = ECPrivateKey.fromString(privateKeyString);
      expect(privateKey.toString(), privateKeyString);
    });

    test('Public Key to string and back', () {
      final publicKeyString = ecKeypair.publicKey.toString();
      final publicKey = ECPublicKey.fromString(publicKeyString);
      expect(publicKey.toString(), publicKeyString);
    });

    test('Get Public Key from Privat Key', () {
      final publicKeyString = ecKeypair.privateKey.publicKey.toString();
      expect(publicKeyString, ecKeypair.publicKey.toString());
    });

    test('Sign and Verify deprecated', () {
      final signature =
          // ignore: deprecated_member_use_from_same_package
          ecKeypair.privateKey.createSignature(utf8.decode(message));
      final verified =
          // ignore: deprecated_member_use_from_same_package
          ecKeypair.publicKey.verifySignature(utf8.decode(message), signature);
      expect(verified, isTrue);
    });

    test('Sign and Verify SHA-256', () {
      final signature = ecKeypair.privateKey.createSHA256Signature(message);
      final verified =
          ecKeypair.publicKey.verifySHA256Signature(message, signature);
      expect(verified, isTrue);
    });

    test('Sign and Verify SHA-512', () {
      final signature = ecKeypair.privateKey.createSHA512Signature(message);
      final verified =
          ecKeypair.publicKey.verifySHA512Signature(message, signature);
      expect(verified, isTrue);
    });
  });
}
