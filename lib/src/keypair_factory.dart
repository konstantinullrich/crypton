import 'package:crypton/crypton.dart';

abstract class KeypairFactory {
  /// Create a fresh [KeypairFactory]
  KeypairFactory();

  /// Generate a random [Keypair]
  Keypair fromRandom();

  /// Generate a random [Keypair] asynchronously
  Future<Keypair> fromRandomAsync();
}
