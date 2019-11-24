import 'package:crypton/crypton.dart';

void main() {
  RSAKeypair rsaKeypair = RSAKeypair.fromRandom();;
  String message = DateTime.now().millisecondsSinceEpoch.toRadixString(16);

  String privateKeyString = rsaKeypair.privateKey.toString();
  String publicKeyString = rsaKeypair.publicKey.toString();
  String signature = rsaKeypair.privateKey.createSignature(message);
  bool verified = rsaKeypair.publicKey.verifySignature(message, signature);

  print("Your Private Key\n $privateKeyString\n---");
  print("Your Public Key\n $publicKeyString\n---");

  if (verified) {
    print("The Signature is verified!");
  } else {
    print("The Signature could not be verified!");
  }
}
