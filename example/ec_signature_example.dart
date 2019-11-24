import 'package:crypton/crypton.dart';

void main() {
  ECKeypair ecKeypair = ECKeypair.fromRandom();
  String message = DateTime.now().millisecondsSinceEpoch.toRadixString(16);

  String privateKeyString = ecKeypair.privateKey.toString();
  String publicKeyString = ecKeypair.publicKey.toString();
  String signature = ecKeypair.privateKey.createSignature(message);
  bool verified = ecKeypair.publicKey.verifySignature(message, signature);

  print("Your Private Key\n $privateKeyString\n---");
  print("Your Public Key\n $publicKeyString\n---");

  print(ecKeypair.privateKey.createSignature(message));
  print(ecKeypair.privateKey.createSignature(message));
  if (verified) {
    print("The Signature is verified!");
  } else {
    print("The Signature could not be verified!");
  }
}
