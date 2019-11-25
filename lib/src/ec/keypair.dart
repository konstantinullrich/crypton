import 'package:pointycastle/export.dart' as pointy;
import 'package:crypton/crypton.dart';

import 'helper.dart';

class ECKeypair implements Keypair {
  ECPrivateKey _privateKey;
  ECPublicKey _publicKey;

  ECKeypair();
  ECKeypair.fromRandom() {

    pointy.ECKeyGeneratorParameters keyParams = pointy.ECKeyGeneratorParameters(pointy.ECCurve_secp256k1());

    pointy.ECKeyGenerator generator = pointy.ECKeyGenerator();
    generator.init(withRandom(keyParams));

    pointy.AsymmetricKeyPair<pointy.PublicKey, pointy.PrivateKey> pair =
    generator.generateKeyPair();
    pointy.ECPublicKey publicKey = pair.publicKey;
    pointy.ECPrivateKey privateKey = pair.privateKey;

    pointy.ECPoint Q = publicKey.Q;
    this._publicKey = ECPublicKey(Q.x.toBigInteger(), Q.y.toBigInteger());
    this._privateKey = ECPrivateKey(privateKey.d);
  }

  @override
  ECPrivateKey get privateKey => this._privateKey;

  @override
  ECPublicKey get publicKey => this._publicKey;
}
