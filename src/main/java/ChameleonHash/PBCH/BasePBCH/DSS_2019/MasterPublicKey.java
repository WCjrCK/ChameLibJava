package ChameleonHash.PBCH.BasePBCH.DSS_2019;

import ChameleonHash.CH.Components.PublicKey;
import ChameleonHash.PBCH.Components.MasterSecretKey;
import utils.ElementCounter;

public class MasterPublicKey extends MasterSecretKey {
    protected PublicKey CHET_pk;
    protected Encryption.ABE.FAME.MasterPublicKey FAME_mpk;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
