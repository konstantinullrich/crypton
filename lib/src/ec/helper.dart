import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

ParametersWithRandom withRandom(var keyParams) {
  Random randomSeed = Random.secure();
  Uint8List seed = Uint8List.fromList(List<int>.generate(32, (_) => randomSeed.nextInt(256)));
  FortunaRandom fortunaRandom = FortunaRandom();
  fortunaRandom.seed(KeyParameter(seed));
  return ParametersWithRandom(keyParams, NativeDartRandom());
}

class NativeDartRandom implements SecureRandom {
  final Random random = Random.secure();

  @override
  String get algorithmName => "dart.math.Random.secure()";

  @override
  BigInt nextBigInteger(int bitLength) {
    // produces a string of length [bitLength] and then parses it with BigInt.parse
    return BigInt.parse(
      Iterable.generate(
        bitLength,
            (_) => random.nextBool() ? "1" : "0",
      ).join(""),
      radix: 2,
    );
  }

  @override
  Uint8List nextBytes(int count) =>
      Uint8List.fromList(List.generate(count, (_) => nextUint8()));

  @override
  int nextUint8() => random.nextInt(256);

  @override
  int nextUint16() => random.nextInt(256 * 256);

  @override
  int nextUint32() => random.nextInt(256 * 256 * 256 * 256);

  @override
  void seed(CipherParameters params) {
    throw UnsupportedError("Seed not supported for this SecureRandom");
  }
}
