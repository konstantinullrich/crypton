import 'package:crypton/crypton.dart';

void main() {
  final rsaKeypair = RSAKeypair.fromRandom();
  final message = DateTime.now().millisecondsSinceEpoch.toRadixString(16);

  final privateKeyString = rsaKeypair.privateKey.toString();
  final publicKeyString = rsaKeypair.publicKey.toString();
  final encrypted = rsaKeypair.publicKey.encrypt(message);
  final decrypted = rsaKeypair.privateKey.decrypt(encrypted);

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
