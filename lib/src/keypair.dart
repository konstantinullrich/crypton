import 'package:crypton/crypton.dart';

abstract class Keypair {
  Keypair(String seed);
  Keypair.fromRandom();

  PublicKey get publicKey => null;
  PrivateKey get privateKey => null;
}
