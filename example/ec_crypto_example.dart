import 'dart:convert';

import 'package:pointycastle/export.dart' as pointy;

import 'package:crypton/crypton.dart';

Map<String, pointy.ECPoint> generateRandom(ECPublicKey ecPublicKey) {
  var secp256k1 = pointy.ECCurve_secp256k1();
  var r = BigInt.parse('61778932634145445713225480677147857250287515219632259034016499480887701935746');
  var R = secp256k1.G * r;
  var S = ecPublicKey.asPointyCastle.Q * r;
  print('S \nx: ${S.x.toString()}\ny: ${S.y.toString()}');
  return { 'R': R, 'S': S };
}

pointy.ECPoint getSFromPrivateKeyAndR(ECPrivateKey ecPrivateKey, pointy.ECPoint R) {
  var S = R * BigInt.parse(ecPrivateKey.toString(), radix: 16);
  print('S from R \nx: ${S.x.toString()}\ny: ${S.y.toString()}');
  return S;
}



void main() {
  var ecKeypair = ECKeypair.fromRandom();
  var message = DateTime.now().millisecondsSinceEpoch.toRadixString(16);

  var RandS = generateRandom(ecKeypair.publicKey);
  print('');
  var S2 = getSFromPrivateKeyAndR(ecKeypair.privateKey, RandS['R']);

  var _cipher = pointy.BlockCipher('AES/ECB');
  _cipher.init(true, pointy.KeyParameter(utf8.encode(RandS['S'].x.toString())));
  var result = base64Encode(_cipher.process(utf8.encode(message)));
  print(result);
}
