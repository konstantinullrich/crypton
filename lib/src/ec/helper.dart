import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

ParametersWithRandom withRandom(ECKeyGeneratorParameters keyParams) {
  final randomSeed = Random.secure();
  final seed = Uint8List.fromList(
      List<int>.generate(32, (_) => randomSeed.nextInt(256)));
  final fortunaRandom = FortunaRandom();
  fortunaRandom.seed(KeyParameter(seed));
  return ParametersWithRandom(keyParams, fortunaRandom);
}
