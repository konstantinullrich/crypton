import 'dart:convert';
import 'dart:typed_data';

import 'package:crypton/crypton.dart';
import 'package:test/test.dart';

void main() {
  group('A group of RSA Key Tests', () {
    RSAKeypair rsaKeypair;
    Uint8List message;

    setUp(() {
      rsaKeypair = RSAKeypair.fromRandom(keySize: 2048);
      message =
          utf8.encode(DateTime.now().millisecondsSinceEpoch.toRadixString(16));
    });

    test('Private Key to String and back', () {
      var privateKeyString = rsaKeypair.privateKey.toString();
      var privateKey = RSAPrivateKey.fromString(privateKeyString);
      expect(privateKey.toString(), privateKeyString);
    });

    test('Public Key to string and back', () {
      var publicKeyString = rsaKeypair.publicKey.toString();
      var publicKey = RSAPublicKey.fromString(publicKeyString);
      expect(publicKey.toString(), publicKeyString);
    });

    test('Get Public Key from Privat Key', () {
      var publicKeyString = rsaKeypair.privateKey.publicKey.toString();
      expect(publicKeyString, rsaKeypair.publicKey.toString());
    });

    test('Get Public Key from PEM-String', () {
      var publicKeyString = rsaKeypair.publicKey.toString();
      var publicKey = RSAPublicKey.fromPEM(rsaKeypair.publicKey.toPEM());
      expect(publicKey.toString(), publicKeyString);
    });

    test('Get Private Key from PEM-String', () {
      var privateKeyString = rsaKeypair.privateKey.toString();
      var privateKey = RSAPrivateKey.fromPEM(rsaKeypair.privateKey.toPEM());
      expect(privateKey.toString(), privateKeyString);
    });

    test('Sign and Verify SHA-256', () {
      var signature = rsaKeypair.privateKey.createSHA256Signature(message);
      var verified =
          rsaKeypair.publicKey.verifySHA256Signature(message, signature);
      expect(verified, isTrue);
    });
    test('Sign and Verify SHA-512', () {
      var signature = rsaKeypair.privateKey.createSHA512Signature(message);
      var verified =
          rsaKeypair.publicKey.verifySHA512Signature(message, signature);
      expect(verified, isTrue);
    });

    test('Encrypt and Decrypt data', () {
      var encrypted = rsaKeypair.publicKey.encryptData(message);
      var decrypted = rsaKeypair.privateKey.decryptData(encrypted);
      expect(decrypted, message);
    });

    test('Encrypt and Decrypt string', () {
      var encrypted = rsaKeypair.publicKey.encrypt(utf8.decode(message));
      var decrypted = utf8.encode(rsaKeypair.privateKey.decrypt(encrypted));
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
    ECKeypair ecKeypair;
    Uint8List message;

    setUp(() {
      ecKeypair = ECKeypair.fromRandom();
      message =
          utf8.encode(DateTime.now().millisecondsSinceEpoch.toRadixString(16));
    });

    test('Private Key to String and back', () {
      var privateKeyString = ecKeypair.privateKey.toString();
      var privateKey = ECPrivateKey.fromString(privateKeyString);
      expect(privateKey.toString(), privateKeyString);
    });

    test('Public Key to string and back', () {
      var publicKeyString = ecKeypair.publicKey.toString();
      var publicKey = ECPublicKey.fromString(publicKeyString);
      expect(publicKey.toString(), publicKeyString);
    });

    test('Get Public Key from Privat Key', () {
      var publicKeyString = ecKeypair.privateKey.publicKey.toString();
      expect(publicKeyString, ecKeypair.publicKey.toString());
    });

    test('Sign and Verify SHA-256', () {
      var signature = ecKeypair.privateKey.createSHA256Signature(message);
      var verified =
          ecKeypair.publicKey.verifySHA256Signature(message, signature);
      expect(verified, isTrue);
    });

    test('Sign and Verify SHA-512', () {
      var signature = ecKeypair.privateKey.createSHA512Signature(message);
      var verified =
          ecKeypair.publicKey.verifySHA512Signature(message, signature);
      expect(verified, isTrue);
    });
  });
}
