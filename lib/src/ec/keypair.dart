import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pointy;
import 'package:crypton/crypton.dart';

class ECKeypair implements Keypair {
  ECPrivateKey _privateKey;
  ECPublicKey _publicKey;

  ECKeypair();
  ECKeypair.fromRandom() {
    Random randomSeed = Random.secure();
    Uint8List seed = Uint8List.fromList(List<int>.generate(32, (_) => randomSeed.nextInt(256)));
    pointy.ECKeyGeneratorParameters keyParams = pointy.ECKeyGeneratorParameters(pointy.ECCurve_secp256k1());

    pointy.FortunaRandom fortunaRandom = pointy.FortunaRandom();
    fortunaRandom.seed(pointy.KeyParameter(seed));

    pointy.ECKeyGenerator generator = pointy.ECKeyGenerator();
    generator.init(pointy.ParametersWithRandom(keyParams, fortunaRandom));

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
