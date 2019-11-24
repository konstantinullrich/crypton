class PublicKey {
  PublicKey();

  PublicKey.fromString(String publicKeyString);

  bool verifySignature(String message, String signature) => null;

  String encrypt(String message) => null;

  @override
  String toString() => super.toString();
}