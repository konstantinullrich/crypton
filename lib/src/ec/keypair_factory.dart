import 'package:crypton/crypton.dart';

/// [KeypairFactory] using the EC Algorithm
class ECKeypairFactory implements KeypairFactory {
  /// Create a fresh [ECKeypairFactory]
  ECKeypairFactory();

  /// Generate a random [ECKeypair]
  @override
  ECKeypair fromRandom() => ECKeypair.fromRandom();

  /// Generate a random [ECKeypair] asynchronously
  @override
  Future<ECKeypair> fromRandomAsync() async =>
      Future(() => ECKeypair.fromRandom());
}
