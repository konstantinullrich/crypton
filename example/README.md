# Examples

## Encryption and Decryption
````dart
  RSAKeypair rsaKeypair = RSAKeypair.fromRandom();
  String message = DateTime.now().millisecondsSinceEpoch.toRadixString(16);

  String encrypted = rsaKeypair.publicKey.encrypt(message);
  String decrypted = rsaKeypair.privateKey.decrypt(encrypted);
````

## Signing and Verifying
##### Using RSA
````dart
  RSAKeypair rsaKeypair = RSAKeypair.fromRandom();
  String message = DateTime.now().millisecondsSinceEpoch.toRadixString(16);

  String signature = rsaKeypair.privateKey.createSignature(message);
  bool verified = rsaKeypair.publicKey.verifySignature(message, signature);
````
##### Using EC
````dart
  ECKeypair ecKeypair = ECKeypair.fromRandom();
  String message = DateTime.now().millisecondsSinceEpoch.toRadixString(16);

  String signature = ecKeypair.privateKey.createSignature(message);
  bool verified = ecKeypair.publicKey.verifySignature(message, signature);
````