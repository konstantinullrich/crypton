import 'package:pointycastle/export.dart' as pointy;

class ECPoint {
  final BigInt x;
  final BigInt y;
  final bool withCompression;
  static final pointy.ECDomainParameters curve = pointy.ECCurve_secp256k1();

  /// Create an [ECPoint] on a elliptic Curve
  ECPoint(this.x, this.y, [this.withCompression = false]);

  /// Export a [ECPoint] as Pointy Castle ECPoint
  pointy.ECPoint get asPointyCastle => curve.curve.createPoint(x, y, withCompression);
}