import 'package:crypton/crypton.dart';

class PrivateKey {
  PrivateKey();

  PrivateKey.fromString(String privateKeyString);

  String createSignature(String message) => null;

  String decrypt(String message) => null;

  PublicKey get publicKey => null;

  @override
  String toString() => super.toString();
}
