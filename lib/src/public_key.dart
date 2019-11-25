class PublicKey {
  PublicKey();

  PublicKey.fromString(String publicKeyString);

  bool verifySignature(String message, String signature) => null;

  @override
  String toString() => super.toString();
}
