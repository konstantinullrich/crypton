abstract class PublicKey {
  PublicKey();

  /// Create an [PublicKey] from the given String.
  PublicKey.fromString(String publicKeyString);

  bool verifySignature(String message, String signature) => null;

  /// Export a [PublicKey] as String which can be reversed using [PublicKey.fromString].
  @override
  String toString() => super.toString();
}
