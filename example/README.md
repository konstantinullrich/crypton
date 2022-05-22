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

  String signature = rsaKeypair.privateKey.createSHA256Signature(utf8.encode(message) as Uint8List);
  bool verified = rsaKeypair.publicKey.verifySHA256Signature(message, signature);
````
##### Using EC
````dart
  ECKeypair ecKeypair = ECKeypair.fromRandom();
  String message = DateTime.now().millisecondsSinceEpoch.toRadixString(16);

  String signature = ecKeypair.privateKey.createSHA256Signature(utf8.encode(message) as Uint8List);
  bool verified = ecKeypair.publicKey.verifySHA256Signature(message, signature);
````
