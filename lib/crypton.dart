library crypton;

export 'src/private_key.dart';
export 'src/public_key.dart';
export 'src/keypair.dart';
export 'src/keypair_factory.dart';

/// Rivest-Shamir-Adleman Cryptography (RSA)
///
/// [RSAPrivateKey] can be used to sign and decrypt data using the RSA Algorithm
/// [RSAPublicKey] can be used to verify signatures and encrypt data using RSA
/// [RSAKeypair] is used to generate a pair of a [RSAPrivateKey] and a [RSAPublicKey]
/// [RSAKeypairFactory] is used to generate a [RSAKeypair]
export 'src/rsa/private_key.dart';
export 'src/rsa/public_key.dart';
export 'src/rsa/keypair.dart';
export 'src/rsa/keypair_factory.dart';

/// Elliptic Curve Cryptography (ECC)
///
/// [ECPrivateKey] can be used to sign [String]s using ECC
/// [ECPublicKey] can be used to verify signatures using ECC
/// [ECKeypair] is used to generate a pair of a [ECPrivateKey] and a [ECPublicKey]
/// [ECKeypairFactory] is used to generate a [ECKeypair]
/// [ECPoint] is a Point on the elliptic Curve
export 'src/ec/private_key.dart';
export 'src/ec/public_key.dart';
export 'src/ec/keypair.dart';
export 'src/ec/keypair_factory.dart';
export 'src/ec/ecpoint.dart';
