package Signature;

import EllipticCurve.Curve.CurveName;
import ChameleonHash.SchemeCurveRequire;

import static ChameleonHash.SchemeCurveRequire.SYMMETRIC;

public enum SName {
    BLS(SYMMETRIC)
    ;

    public final SchemeCurveRequire schemeCurveRequire;

    SName(SchemeCurveRequire schemeCurveRequire) {
        this.schemeCurveRequire = schemeCurveRequire;
    }

    public boolean checkCurve(CurveName curveName) {
        if (schemeCurveRequire == SYMMETRIC && !curveName.isSymmetic()) return false;
        return true;
    }
}
