package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import utils.ElementCounter;

public class Identity extends ChameleonHash.PBCH.RevocablePBCH.Components.Identity {
    Encryption.ABE.RevocableABE.XNM_2021.Identity RABE_id;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
