package Commitment.EQUAL_DL;

import EllipticCurve.Curve.Curve;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Proof extends Commitment.Components.Proof<Proof, Witness> {
    protected Curve curve;
    public Scalar gamma;
    public MultivePoint alpha_1, alpha_2;

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
        gamma = o.gamma;
        alpha_1 = o.alpha_1;
        alpha_2 = o.alpha_2;
    }

    public final boolean Check(Witness data) {
        Scalar beta = H(String.format("%s|%s|%s|%s", data.y_1, data.y_2, alpha_1, alpha_2));
        return data.g_1.pow(gamma).div(alpha_1).isEqual(data.y_1.pow(beta)) &&
                data.g_2.pow(gamma).div(alpha_2).isEqual(data.y_2.pow(beta));
    }
}
