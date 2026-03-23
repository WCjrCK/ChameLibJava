package ChameleonHash.PBCH.RevocablePBCH.TMM_2022;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class MasterPublicKey extends ChameleonHash.PBCH.RevocablePBCH.Components.MasterPublicKey {
    Encryption.ABE.RevocableABE.TMM_2022.MasterPublicKey RABE_mpk;
    MultivePoint g;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
