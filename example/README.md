# Examples

## Encryption and Decryption
````dart
  RSAKeypair rsaKeypair = RSAKeypair.fromRandom();
  String message = DateTime.now().millisecondsSinceEpoch.toRadixString(16);

  String privateKeyString = rsaKeypair.privateKey.toString();
  String publicKeyString = rsaKeypair.publicKey.toString();
  String encrypted = rsaKeypair.publicKey.encrypt(message);
  String decrypted = rsaKeypair.privateKey.decrypt(encrypted);
````

## Signing and Verifying
````dart
  RSAKeypair rsaKeypair = RSAKeypair.fromRandom();
  String message = DateTime.now().millisecondsSinceEpoch.toRadixString(16);

  String privateKeyString = rsaKeypair.privateKey.toString();
  String publicKeyString = rsaKeypair.publicKey.toString();
  String signature = rsaKeypair.privateKey.createSignature(message);
  bool verified = rsaKeypair.publicKey.verifySignature(message, signature);
````