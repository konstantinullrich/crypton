import 'package:crypton/crypton.dart';

void main() {
  var rsaKeypair = RSAKeypair.fromRandom();
  var message = DateTime.now().millisecondsSinceEpoch.toRadixString(16);

  var privateKeyString = rsaKeypair.privateKey.toString();
  var publicKeyString = rsaKeypair.publicKey.toString();
  var signature = rsaKeypair.privateKey.createSignature(message);
  var verified = rsaKeypair.publicKey.verifySignature(message, signature);

  print('Your Private Key\n $privateKeyString\n---');
  print('Your Public Key\n $publicKeyString\n---');

  if (verified) {
    print('The Signature is verified!');
  } else {
    print('The Signature could not be verified!');
  }
}
