import 'package:crypton/crypton.dart';

abstract class Keypair {
  /// Create a [Keypair] using an [PrivateKey]
  Keypair(PrivateKey privateKey);

  /// Generate a random [Keypair]
  Keypair.fromRandom();

  /// Get the [PublicKey] associated [PrivateKey]
  PublicKey get publicKey => null;

  /// Get the [PrivateKey] associated [PublicKey]
  PrivateKey get privateKey => null;
}
