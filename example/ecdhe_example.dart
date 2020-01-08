import 'package:crypton/crypton.dart';

void main() {
  var alice = ECKeypair.fromRandom();
  var bob = ECKeypair.fromRandom();

  var qk = ECEncryptionPair(alice.privateKey, bob.publicKey);
  var q2 = ECEncryptionPair(bob.privateKey, alice.publicKey);
  print(qk.encryptionKey);
  print(q2.encryptionKey);
}