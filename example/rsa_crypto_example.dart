import 'package:crypton/crypton.dart';

void main() {
  RSAKeypair rsaKeypair = RSAKeypair.fromRandom();;
  String message = DateTime.now().millisecondsSinceEpoch.toRadixString(16);

  String privateKeyString = rsaKeypair.privateKey.toString();
  String publicKeyString = rsaKeypair.publicKey.toString();
  String encrypted = rsaKeypair.publicKey.encrypt(message);
  String decrypted = rsaKeypair.privateKey.decrypt(encrypted);

  print("Your Private Key\n $privateKeyString\n---");
  print("Your Public Key\n $publicKeyString\n---");
  print("Encrypted Message\n $encrypted\n---");
  print("Decrypted Message\n $decrypted\n---");

  if (decrypted == message) {
    print("The Message was successfuly decrypted!");
  } else {
    print("Failed to decrypted the Message!");
  }
}
