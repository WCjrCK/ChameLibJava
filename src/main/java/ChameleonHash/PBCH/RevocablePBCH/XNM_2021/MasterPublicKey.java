package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import ChameleonHash.CH.CHET.Components.PublicKey;
import utils.ElementCounter;

public class MasterPublicKey extends ChameleonHash.PBCH.RevocablePBCH.Components.MasterPublicKey {
    protected PublicKey CHET_pk;
    Encryption.ABE.RevocableABE.XNM_2021.MasterPublicKey RABE_mpk;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
