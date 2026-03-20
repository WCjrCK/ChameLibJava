package Encryption.ABE.RevocableABE.TMM_2022;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class Identity extends Encryption.ABE.RevocableABE.Components.Identity {
    protected MultivePoint id;

    @Override
    public int hashCode() {
        return id.toString().hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof Identity) {
            return id.isEqual(((Identity) obj).id);
        }
        return false;
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
