package Signature.BLS;

import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveFactory;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.PointRepresentation;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

public class PublicParam extends Signature.Components.PublicParam {
    protected MultivePoint g;

    public Curve curve;

    protected PublicParam(CurveName curveName, Map<String, Object> params) {
        super(params);
        curve = CurveFactory.create(curveName, PointRepresentation.MULTIVE, (Map<String, Object>) params.get("curve_param"));
    }

    public final MultivePoint H(String x) {
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

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }

    @Override
    public final Message createMessage(String msg) {
        return new Message(msg);
    }

}
