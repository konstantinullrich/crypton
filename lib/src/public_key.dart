import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pointy;

abstract class PublicKey {
  PublicKey();

  /// Create an [PublicKey] from the given String.
  PublicKey.fromString(String publicKeyString);

  /// Verify the signature of a SHA256-hashed message signed with the associated [PrivateKey]
  @Deprecated('For SHA256 signature verification use verifySHA256Signature')
  bool verifySignature(String message, String signature) =>
      throw UnimplementedError(
          'verifySignature(String message, String signature) is not implemented yet!');

  /// Verify the signature of a SHA256-hashed message signed with the associated [PrivateKey]
  bool verifySHA256Signature(Uint8List message, Uint8List signature) =>
      throw UnimplementedError(
          'verifySHA256Signature(Uint8List message, Uint8List signature) is not implemented yet!');

  /// Verify the signature of a SHA512-hashed message signed with the associated [PrivateKey]
  bool verifySHA512Signature(Uint8List message, Uint8List signature) =>
      throw UnimplementedError(
          'verifySHA512Signature(Uint8List message, Uint8List signature) is not implemented yet!');

  /// Export a [PublicKey] as Pointy Castle PublicKey
  pointy.PublicKey get asPointyCastle =>
      throw UnimplementedError('asPointyCastle is not implemented yet!');

  /// Export a [PublicKey] as String which can be reversed using [PublicKey.fromString].
  @override
  String toString() => super.toString();
}
