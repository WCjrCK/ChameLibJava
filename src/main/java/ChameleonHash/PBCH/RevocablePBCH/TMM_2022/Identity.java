package ChameleonHash.PBCH.RevocablePBCH.TMM_2022;

import utils.ElementCounter;

public class Identity extends ChameleonHash.PBCH.RevocablePBCH.Components.Identity {
    Encryption.ABE.RevocableABE.TMM_2022.Identity RABE_id;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
