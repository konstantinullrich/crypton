import 'package:pointycastle/export.dart' as pointy;
import 'package:crypton/crypton.dart';

import 'helper.dart';

/// [Keypair] using EC Algorithm
class ECKeypair implements Keypair {
  ECPrivateKey _privateKey;
  ECPublicKey _publicKey;

  /// Create a [ECKeypair] using an [ECPrivateKey]
  ECKeypair(this._privateKey) : _publicKey = _privateKey.publicKey;

  /// Generate a random [ECKeypair]
  ECKeypair.fromRandom() {
    var keyParams = pointy.ECKeyGeneratorParameters(pointy.ECCurve_secp256k1());

    var generator = pointy.ECKeyGenerator();
    generator.init(withRandom(keyParams));

    var pair = generator.generateKeyPair();
    pointy.ECPublicKey publicKey = pair.publicKey;
    pointy.ECPrivateKey privateKey = pair.privateKey;

    var Q = publicKey.Q;
    _publicKey = ECPublicKey(Q.x.toBigInteger(), Q.y.toBigInteger());
    _privateKey = ECPrivateKey(privateKey.d);
  }

  /// Get the [ECPublicKey] associated [ECPrivateKey]
  @override
  ECPublicKey get publicKey => _publicKey;

  /// Get the [ECPrivateKey] associated [ECPublicKey]
  @override
  ECPrivateKey get privateKey => _privateKey;
}
