import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pointy;
import 'package:crypton/crypton.dart';

class RSAKeypair implements Keypair {
  RSAPrivateKey _privateKey;
  RSAPublicKey _publicKey;

  RSAKeypair();
  RSAKeypair.fromRandom() {
    pointy.RSAKeyGeneratorParameters keyParams =
        pointy.RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 12);

    pointy.FortunaRandom fortunaRandom = pointy.FortunaRandom();
    Random random = Random.secure();
    List<int> seeds = [];
    for (int i = 0; i < 32; i++) {
      seeds.add(random.nextInt(255));
    }
    fortunaRandom.seed(pointy.KeyParameter(Uint8List.fromList(seeds)));

    pointy.ParametersWithRandom randomParams =
        pointy.ParametersWithRandom(keyParams, fortunaRandom);
    pointy.RSAKeyGenerator generator = pointy.RSAKeyGenerator();
    generator.init(randomParams);

    pointy.AsymmetricKeyPair<pointy.PublicKey, pointy.PrivateKey> pair =
        generator.generateKeyPair();
    pointy.RSAPublicKey publicKey = pair.publicKey;
    pointy.RSAPrivateKey privateKey = pair.privateKey;

    this._publicKey = RSAPublicKey(publicKey.modulus, publicKey.exponent);
    this._privateKey = RSAPrivateKey(
        privateKey.modulus, privateKey.exponent, privateKey.p, privateKey.q);
  }

  @override
  RSAPrivateKey get privateKey => this._privateKey;

  @override
  RSAPublicKey get publicKey => this._publicKey;
}
