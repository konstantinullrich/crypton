import 'package:crypton/crypton.dart';

abstract class PrivateKey {
  PrivateKey();

  /// Create an [PrivateKey] from the given String.
  PrivateKey.fromString(String privateKeyString);

  String createSignature(String message) => null;

  /// Get the [PublicKey] of the [PrivateKey]
  PublicKey get publicKey => null;

  /// Export a [PrivateKey] as String which can be reversed using [PrivateKey.fromString].
  @override
  String toString() => super.toString();
}
