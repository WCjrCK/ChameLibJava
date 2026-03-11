package scheme.IBCH.implement.ZSS_2003.S1;

import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.AdditivePoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.BitSet;
import java.util.Map;

public class PublicParam extends scheme.Components.PublicParam {
    public AdditivePoint P;
    public AdditivePoint P_pub; // G_1

    public PublicParam(CurveName curveName, Map<String, Object> params) {
        super(curveName, params);
    }

    @Override
    public final String toString() {
        return "P = " + P.toString() + " | P_pub = " + P_pub.toString();
    }

    public final AdditivePoint H0(String x) {
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(x.getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return curve.HashToG1(hash);
    }

    public final BigInteger H1(String x) {
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(x.getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return curve.HashToZp(hash).toBigInteger();
    }
}
