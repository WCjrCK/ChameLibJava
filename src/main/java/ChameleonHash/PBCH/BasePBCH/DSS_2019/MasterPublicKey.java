package ChameleonHash.PBCH.BasePBCH.DSS_2019;

import ChameleonHash.CH.Components.PublicKey;
import utils.ElementCounter;

public class MasterPublicKey extends ChameleonHash.PBCH.Components.MasterPublicKey {
    protected PublicKey CHET_pk;
    protected Encryption.ABE.BaseABE.FAME.MasterPublicKey FAME_mpk;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
