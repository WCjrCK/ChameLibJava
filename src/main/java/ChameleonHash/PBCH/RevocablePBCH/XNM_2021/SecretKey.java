package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import utils.ElementCounter;

public class SecretKey extends ChameleonHash.PBCH.RevocablePBCH.Components.SecretKey {
    ChameleonHash.CH.CHET.Components.SecretKey CHET_sk;
    Encryption.ABE.RevocableABE.XNM_2021.SecretKey RABE_sk;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
