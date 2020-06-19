import 'package:crypton/crypton.dart';

void main() {
  var rsaKeypair = RSAKeypair.fromRandom();
  var message = DateTime.now().millisecondsSinceEpoch.toRadixString(16);

  var privateKeyString = rsaKeypair.privateKey.toString();
  var publicKeyString = rsaKeypair.publicKey.toString();
  var encrypted = rsaKeypair.publicKey.encrypt(message);
  var decrypted = rsaKeypair.privateKey.decrypt(encrypted);

  print('Your Private Key\n $privateKeyString\n---');
  print('Your Public Key\n $publicKeyString\n---');
  print('Encrypted Message\n $encrypted\n---');
  print('Decrypted Message\n $decrypted\n---');

  if (decrypted == message) {
    print('The Message was successfully decrypted!');
  } else {
    print('Failed to decrypted the Message!');
  }
}
