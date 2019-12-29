import 'package:crypton/crypton.dart';

abstract class Keypair {
  // TODO: Add Documentation
  Keypair(PrivateKey privateKey);

  // TODO: Add Documentation
  Keypair.fromRandom();

  // TODO: Add Documentation
  PublicKey get publicKey => null;

  // TODO: Add Documentation
  PrivateKey get privateKey => null;
}
