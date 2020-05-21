import 'package:crypton/crypton.dart';
import 'package:test/test.dart';

void main() {
  group('A group of RSA Key Tests', () {
    RSAKeypair rsaKeypair;
    String message;

    setUp(() {
      rsaKeypair = RSAKeypair.fromRandom();
      message = DateTime.now().millisecondsSinceEpoch.toRadixString(16);
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

    test('Sign and Verify', () {
      var signature = rsaKeypair.privateKey.createSignature(message);
      var verified = rsaKeypair.publicKey.verifySignature(message, signature);
      expect(verified, isTrue);
    });

    test('Encrypt and Decrypt', () {
      var encrypted = rsaKeypair.publicKey.encrypt(message);
      var decrypted = rsaKeypair.privateKey.decrypt(encrypted);
      expect(message, decrypted);
    });
  });

  group('A group of EC Key Tests', () {
    ECKeypair ecKeypair;
    String message;

    setUp(() {
      ecKeypair = ECKeypair.fromRandom();
      message = DateTime.now().millisecondsSinceEpoch.toRadixString(16);
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

    test('Sign and Verify', () {
      var signature = ecKeypair.privateKey.createSignature(message);
      var verified = ecKeypair.publicKey.verifySignature(message, signature);
      expect(verified, isTrue);
    });
  });
}
