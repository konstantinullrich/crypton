import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

ParametersWithRandom withRandom(var keyParams) {
  var randomSeed = Random.secure();
  var seed = Uint8List.fromList(
      List<int>.generate(32, (_) => randomSeed.nextInt(256)));
  var fortunaRandom = FortunaRandom();
  fortunaRandom.seed(KeyParameter(seed));
  return ParametersWithRandom(keyParams, fortunaRandom);
}
