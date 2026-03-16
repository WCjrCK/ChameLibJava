package Commitment.DL.NIZK_DL;

import EllipticCurve.Curve.Curve;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Proof extends Commitment.Components.Proof<Proof, Relation> {
    protected Curve curve;
    public MultivePoint alpha;
    public Scalar gamma;

    protected Scalar H(String m) {
        byte[] hash;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            hash = digest.digest(m.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return curve.HashToZp(hash);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }

    @Override
    public void CopyFrom(Proof o) {
        curve = o.curve;
        alpha = o.alpha;
        gamma = o.gamma;
    }

    public final boolean Check(Relation data) {
        return data.g.pow(gamma).div(alpha).isEqual(data.y.pow(H(String.format("%s|%s", data.y, alpha))));
    }
}
