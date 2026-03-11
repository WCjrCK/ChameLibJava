package EllipticCurve.Point;

import java.math.BigInteger;

public interface MultivePoint {
    Point mul(Point other);

    Point div(Point other);

    Point pow(BigInteger exponent);

    Point inv();
}
