import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pointy;
import 'package:crypton/crypton.dart';

/// [Keypair] using RSA Algorithm
class RSAKeypair implements Keypair {
  late RSAPrivateKey _privateKey;
  late RSAPublicKey _publicKey;

  /// Create a [RSAKeypair] using an [RSAPrivateKey]
  RSAKeypair(this._privateKey) : _publicKey = _privateKey.publicKey;

  /// Generate a random [RSAKeypair] with a default key size of 2048 bit
  ///
  /// The recommended key size is 4096 but was changed to 2048 to insure backwards comparability
  RSAKeypair.fromRandom({int keySize = 2048}) {
    final keyParams =
        pointy.RSAKeyGeneratorParameters(BigInt.parse('65537'), keySize, 12);

    final fortunaRandom = pointy.FortunaRandom();
    final random = Random.secure();
    final seeds = <int>[];
    for (var i = 0; i < 32; i++) {
      seeds.add(random.nextInt(255));
    }
    fortunaRandom.seed(pointy.KeyParameter(Uint8List.fromList(seeds)));

    final randomParams = pointy.ParametersWithRandom(keyParams, fortunaRandom);
    final generator = pointy.RSAKeyGenerator();
    generator.init(randomParams);

    final pair = generator.generateKeyPair();
    final publicKey = pair.publicKey as pointy.RSAPublicKey;
    final privateKey = pair.privateKey as pointy.RSAPrivateKey;

    _publicKey = RSAPublicKey(publicKey.modulus!, publicKey.exponent!);
    _privateKey = RSAPrivateKey(privateKey.modulus!, privateKey.exponent!,
        privateKey.p!, privateKey.q!);
  }

  /// Get the [RSAPublicKey] associated [RSAPrivateKey]
  @override
  RSAPublicKey get publicKey => _publicKey;

  /// Get the [RSAPrivateKey] associated [RSAPublicKey]
  @override
  RSAPrivateKey get privateKey => _privateKey;
}
