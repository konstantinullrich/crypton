import 'package:pointycastle/export.dart' as pointy;

/// Point on the elliptic Curve
class ECPoint {
  final BigInt/*!*/ x;
  final BigInt/*!*/ y;
  final bool withCompression;
  static final pointy.ECDomainParameters curve = pointy.ECCurve_secp256k1();

  /// Create an [ECPoint] on a elliptic Curve
  ECPoint(this.x, this.y, [this.withCompression = false]);

  /// Export a [ECPoint] as Pointy Castle ECPoint
  pointy.ECPoint get asPointyCastle =>
      curve.curve.createPoint(x, y, withCompression);

  ECPoint operator *(BigInt k) {
    var point = asPointyCastle * k;
    return ECPoint(
        point.x.toBigInteger(), point.y.toBigInteger(), point.isCompressed);
  }
}
