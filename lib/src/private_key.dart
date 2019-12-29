import 'package:pointycastle/export.dart' as pointy;
import 'package:crypton/crypton.dart';

abstract class PrivateKey {
  PrivateKey();

  /// Create an [PrivateKey] from the given String.
  PrivateKey.fromString(String privateKeyString);

  // TODO: Add Documentation
  String createSignature(String message) => null;

  /// Get the [PublicKey] of the [PrivateKey]
  PublicKey get publicKey => null;

  /// Export a [PrivateKey] as Pointy Castle PrivateKey
  pointy.PrivateKey get asPointyCastle => null;

  /// Export a [PrivateKey] as String which can be reversed using [PrivateKey.fromString].
  @override
  String toString() => super.toString();
}
