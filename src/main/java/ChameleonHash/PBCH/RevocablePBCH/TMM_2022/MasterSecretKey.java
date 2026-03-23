package ChameleonHash.PBCH.RevocablePBCH.TMM_2022;

import utils.ElementCounter;

public class MasterSecretKey extends ChameleonHash.PBCH.RevocablePBCH.Components.MasterSecretKey {
    Encryption.ABE.RevocableABE.TMM_2022.MasterSecretKey RABE_msk;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
