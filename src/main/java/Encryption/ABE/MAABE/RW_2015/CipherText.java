package Encryption.ABE.MAABE.RW_2015;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class CipherText extends Encryption.ABE.MAABE.Components.CipherText<CipherText, Policy> {
    MultivePoint C_0;
    MultivePoint[][] C;

    public boolean isEqual(CipherText o) {
        if (C.length != o.C.length) return false;
        if(C[0].length != o.C[0].length) return false;
        for(int i = 0; i < C.length; ++i)
            for (int j = 0; j < C[0].length; ++j) if (!C[i][j].isEqual(o.C[i][j])) return false;
        return C_0.isEqual(o.C_0);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
