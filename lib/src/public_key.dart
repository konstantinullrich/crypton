import 'package:pointycastle/export.dart' as pointy;

abstract class PublicKey {
  // TODO: Add Documentation
  PublicKey();

  /// Create an [PublicKey] from the given String.
  PublicKey.fromString(String publicKeyString);

  // TODO: Add Documentation
  bool verifySignature(String message, String signature) => null;

  /// Export a [PublicKey] as Pointy Castle PublicKey
  pointy.PublicKey get asPointyCastle => null;

  /// Export a [PublicKey] as String which can be reversed using [PublicKey.fromString].
  @override
  String toString() => super.toString();
}
