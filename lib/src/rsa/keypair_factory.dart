import 'package:crypton/crypton.dart';

/// [KeypairFactory] using the RSA Algorithm
class RSAKeypairFactory implements KeypairFactory {
  /// Create a fresh [RSAKeypairFactory]
  RSAKeypairFactory();

  /// Generate a random [RSAKeypair]
  @override
  RSAKeypair fromRandom({int keySize = 2048}) =>
      RSAKeypair.fromRandom(keySize: keySize);

  /// Generate a random [RSAKeypair] asynchronously
  @override
  Future<RSAKeypair> fromRandomAsync({int keySize = 2048}) async =>
      Future(() => RSAKeypair.fromRandom(keySize: keySize));
}
