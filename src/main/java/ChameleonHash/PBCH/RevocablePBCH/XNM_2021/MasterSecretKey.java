package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import ChameleonHash.CH.CHET.Components.SecretKey;
import utils.ElementCounter;

public class MasterSecretKey extends ChameleonHash.PBCH.RevocablePBCH.Components.MasterSecretKey {
    SecretKey CHET_sk;
    Encryption.ABE.RevocableABE.XNM_2021.MasterSecretKey RABE_msk;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
