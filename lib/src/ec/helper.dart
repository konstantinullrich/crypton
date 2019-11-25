import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

ParametersWithRandom withRandom(var keyParams) {
  Random randomSeed = Random.secure();
  Uint8List seed = Uint8List.fromList(
      List<int>.generate(32, (_) => randomSeed.nextInt(256)));
  FortunaRandom fortunaRandom = FortunaRandom();
  fortunaRandom.seed(KeyParameter(seed));
  return ParametersWithRandom(keyParams, fortunaRandom);
}
