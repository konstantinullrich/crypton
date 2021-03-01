import 'package:crypton/crypton.dart';

abstract class Keypair {
  /// Create a [Keypair] using an [PrivateKey]
  Keypair(PrivateKey privateKey);

  /// Generate a random [Keypair]
  Keypair.fromRandom();

  /// Get the [PublicKey] associated [PrivateKey]
  PublicKey get publicKey =>
      throw UnimplementedError('publicKey is not implemented yet!');

  /// Get the [PrivateKey] associated [PublicKey]
  PrivateKey get privateKey =>
      throw UnimplementedError('privateKey is not implemented yet!');
}
