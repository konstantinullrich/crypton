import 'package:crypton/crypton.dart';
import 'package:pointycastle/export.dart' as pointy;

class ECPrivateKey implements PrivateKey {
  pointy.ECPrivateKey _privateKey;
  static pointy.ECCurve_secp256k1 secp256k1 = pointy.ECCurve_secp256k1();

  ECPrivateKey(BigInt d){
    this._privateKey = pointy.ECPrivateKey(d, secp256k1);
  }

  ECPrivateKey.fromString(String privateKeyString) {
    this._privateKey = pointy.ECPrivateKey(
        BigInt.parse(privateKeyString, radix: 16),
        secp256k1
    );
  }

  @override
  String createSignature(String message) => null;

  @override
  ECPublicKey get publicKey {
    pointy.ECPoint Q = secp256k1.G * this._privateKey.d;
    return ECPublicKey(Q.x.toBigInteger(), Q.y.toBigInteger());
  }

  @override
  String toString() => this._privateKey.d.toRadixString(16);

  @override
  String decrypt(String message) {
    // TODO: implement decrypt
    return null;
  }
}