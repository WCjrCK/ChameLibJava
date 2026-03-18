package Encryption.ABE.BaseABE.FAME;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class CipherText extends Encryption.ABE.Components.CipherText<CipherText> {
    protected MultivePoint[][] ct;
    public MultivePoint[] ct_0;
    public MultivePoint ct_p;

    @Override
    public final boolean isEqual(CipherText o) {
        if(ct_0.length != o.ct_0.length) return false;
        if(ct.length != o.ct.length) return false;
        if(ct[0].length != o.ct[0].length) return false;
        for(int i = 0; i < ct_0.length; ++i) {
            if(!ct_0[i].isEqual(o.ct_0[i])) return false;
        }
        for(int i = 0; i < ct.length; ++i) {
            for(int j = 0; j < ct[i].length; ++j) {
                if(!ct[i][j].isEqual(o.ct[i][j])) return false;
            }
        }
        return ct_p.isEqual(o.ct_p);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
