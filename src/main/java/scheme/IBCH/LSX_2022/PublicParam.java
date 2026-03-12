package scheme.IBCH.LSX_2022;

import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Point;
import EllipticCurve.Point.PointRepresentation;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

public class PublicParam extends scheme.Components.PublicParam {
    protected MultivePoint g, g_1, g_2, egg, eg_2g;

    public PublicParam(CurveName curveName, Map<String, Object> params) {
        super(curveName, PointRepresentation.MULTIVE, params);
    }

    @Override
    public final String toString() {
        return "";
    }

    @Override
    public final String TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count((Point) g);
        res.count((Point) g_1);
        res.count((Point) g_2);
        res.count((Point) egg);
        res.count((Point) eg_2g);
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
        Identity res = new Identity();
        MessageDigest messageDigest;
        byte[] hash;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(ID.getBytes(StandardCharsets.UTF_8));
            hash = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        res.ID = curve.HashToZp(hash);
        return res;
    }
}
