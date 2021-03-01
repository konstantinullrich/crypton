import 'package:crypton/crypton.dart';
import 'package:pointycastle/export.dart' as pointy;

import 'helper.dart';

/// [Keypair] using EC Algorithm
class ECKeypair implements Keypair {
  ECPrivateKey /*!*/ _privateKey;
  ECPublicKey /*!*/ _publicKey;

  /// Create a [ECKeypair] using an [ECPrivateKey]
  ECKeypair(this._privateKey) : _publicKey = _privateKey.publicKey;

  /// Generate a random [ECKeypair] on the secp256k1-Curve
  ECKeypair.fromRandom() {
    final keyParams =
        pointy.ECKeyGeneratorParameters(pointy.ECCurve_secp256k1());

    final generator = pointy.ECKeyGenerator();
    generator.init(withRandom(keyParams));

    final pair = generator.generateKeyPair();
    final publicKey = pair.publicKey as pointy.ECPublicKey;
    final privateKey = pair.privateKey as pointy.ECPrivateKey;

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
