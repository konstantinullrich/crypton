import 'package:crypton/crypton.dart';

void main() {
  ECKeypair ecKeypair = ECKeypair.fromRandom();
  String message = DateTime.now().millisecondsSinceEpoch.toRadixString(16);

  String privateKeyString = ecKeypair.privateKey.toString();
  String publicKeyString = ecKeypair.publicKey.toString();
  String signature = ecKeypair.privateKey.createSignature(message);
  bool verified =
      ecKeypair.privateKey.publicKey.verifySignature(message, signature);

  print("Your Private Key\n $privateKeyString\n---");
  print("Your Public Key\n $publicKeyString\n---");

  if (verified) {
    print("The Signature is verified!");
  } else {
    print("The Signature could not be verified!");
  }
}
