import 'dart:typed_data';

import 'package:crypton/crypton.dart';
import 'package:pointycastle/export.dart' as pointy;

abstract class PrivateKey {
  PrivateKey();

  /// Create an [PrivateKey] from the given String.
  PrivateKey.fromString(String privateKeyString);

  /// Sign an message which can be verified using the associated [PublicKey]
  @Deprecated('Use createSHA256Signature for creating SHA-256 signatures')
  String createSignature(String message) => null;

  /// Create a SHA-256 of a [message]
  Uint8List createSHA256Signature(Uint8List message) => null;

  /// Create a SHA-512 of a [message]
  Uint8List createSHA512Signature(Uint8List message) => null;

  /// Get the [PublicKey] of the [PrivateKey]
  PublicKey get publicKey => null;

  /// Export a [PrivateKey] as Pointy Castle PrivateKey
  pointy.PrivateKey get asPointyCastle => null;

  /// Export a [PrivateKey] as String which can be reversed using [PrivateKey.fromString].
  @override
  String toString() => super.toString();
}
