package EllipticCurve.Point;

import java.math.BigInteger;

public interface AdditivePoint {
    Point add(Point other);

    Point sub(Point other);

    Point mul(BigInteger scalar);

    Point neg();
}
