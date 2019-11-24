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
      String privateKeyString = rsaKeypair.privateKey.toString();
      RSAPrivateKey privateKey = RSAPrivateKey.fromString(privateKeyString);
      expect(privateKey.toString(), privateKeyString);
    });

    test('Public Key to string and back', () {
      String publicKeyString = rsaKeypair.publicKey.toString();
      RSAPublicKey publicKey = RSAPublicKey.fromString(publicKeyString);
      expect(publicKey.toString(), publicKeyString);
    });

    test('Sign and Verify', () {
      String signature = rsaKeypair.privateKey.createSignature(message);
      bool verified = rsaKeypair.publicKey.verifySignature(message, signature);
      expect(verified, isTrue);
    });

    test('Encrypt and Decrypt', () {
      String encrypted = rsaKeypair.publicKey.encrypt(message);
      String decrypted = rsaKeypair.privateKey.decrypt(encrypted);
      expect(message, decrypted);
    });
  });
  group('A group of EC Key Tests', () {
    ECKeypair ecKeypair;

    setUp(() {
      ecKeypair = ECKeypair.fromRandom();
    });

    test('Private Key to String and back', () {
      String privateKeyString = ecKeypair.privateKey.toString();
      ECPrivateKey privateKey = ECPrivateKey.fromString(privateKeyString);
      expect(privateKey.toString(), privateKeyString);
    });

    test('Public Key to string and back', () {
      String publicKeyString = ecKeypair.publicKey.toString();
      ECPublicKey publicKey = ECPublicKey.fromString(publicKeyString);
      expect(publicKey.toString(), publicKeyString);
    });
  });
}
