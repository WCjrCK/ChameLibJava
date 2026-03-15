package ChameleonHash.CH.LabelCH.LLA_2012;

import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;

import java.util.HashMap;
import java.util.Map;

public class LabelManager {
    public Map<String, LabelGen> Dict = new HashMap<>();

    public void add(PublicParam pp, PublicKey pk, LabelGen lg) {
        Dict.put(pk.toString(), lg);
    }
    public void get(Label L, PublicParam pp, PublicKey pk) {
        MultivePoint t = pp.curve.getRandomPoint(pp.curveGroup);
        Scalar H_2t = pp.H2(t);
        LabelGen lg = Dict.get(pk.toString());
        L.L = lg.y_1.pow(H_2t);
        L.R = t.mul(lg.omega_1.pow(H_2t));
    }
}
