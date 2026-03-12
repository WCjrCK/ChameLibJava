package scheme.IBCH.CZS_2014;

import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.Point;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

public class PublicParam extends scheme.Components.PublicParam {
    protected AdditivePoint P;
    protected AdditivePoint P_pub;

    public PublicParam(CurveName curveName, Map<String, Object> params) {
        super(curveName, params);
    }

    @Override
    public final String toString() {
        return "P = " + P.toString() + " | P_pub = " + P_pub.toString();
    }

    public final AdditivePoint H(String x) {
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

    public final AdditivePoint H_p(String x) {
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(x.getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return curve.HashToG2(hash);
    }

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count((Point) P);
        res.count((Point) P_pub);
        return res.toString();
    }

    @Override
    public final scheme.Components.Message createMessage(String msg) {
        Message res = new Message();
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(msg.getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        res.m = curve.HashToZp(hash);
        return res;
    }

    @Override
    public final scheme.Components.Identity createIdentity(String ID) {
        return new Identity(ID);
    }
}
