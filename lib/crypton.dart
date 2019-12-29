library crypton;

import 'package:crypton/src/ec/eciespair.dart';

export 'src/private_key.dart';
export 'src/public_key.dart';
export 'src/keypair.dart';

/// Rivest-Shamir-Adleman Cryptography (RSA)
///
/// [RSAPrivateKey] can be used to sign and decrypt data using the RSA Algorithm
/// [RSAPublicKey] can be used to verify signatures and encrypt data using RSA
/// [RSAKeypair] is used to generate a pair of a [RSAPrivateKey] and a [RSAPublicKey]
export 'src/rsa/private_key.dart';
export 'src/rsa/public_key.dart';
export 'src/rsa/keypair.dart';

/// Elliptic Curve Cryptography (ECC)
///
/// [ECPrivateKey] can be used to sign [String]s using ECC and retrieve the key for symmetric encryption from the [ECPoint] R of [ECIESPair]
/// [ECPublicKey] can be used to verify signatures using ECC
/// [ECKeypair] is used to generate a pair of a [ECPrivateKey] and a [ECPublicKey]
/// [ECPoint] is a Point on the elliptic Curve
/// [ECIESPair] is a Pair of [ECPoint]s used to get a key for symmetric encryption
// TODO: Add Documentation
export 'src/ec/private_key.dart';
export 'src/ec/public_key.dart';
export 'src/ec/keypair.dart';
export 'src/ec/ecpoint.dart';
export 'src/ec/eciespair.dart';
