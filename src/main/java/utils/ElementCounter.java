package utils;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.Point;

import static EllipticCurve.Curve.CurveGroup.*;

public class ElementCounter {
    CurveGroup[] idxgroup = {G1, G2, GT, Zp};
    int[] count = new int[idxgroup.length];

    public void count(Point p) {
        for (int i = 0;i < count.length;++i) if (p.group() == idxgroup[i]) {
            count[i] += 1;
            break;
        }
    }

    public void add(ElementCounter o) {
        for (int i = 0;i < count.length;++i) count[i] += o.count[i];
    }

    @Override
    public String toString() {
        StringBuilder res = new StringBuilder();
        for (int i = 0;i < idxgroup.length;++i) {
            if (count[i] > 0) {
                if (res.length() > 0) res.append(" + ");
                if (count[i] > 1) res.append(count[i]);
                res.append(idxgroup[i].name());
            }
        }
        if (res.length() == 0) return "-";
        return res.toString();
    }
}
