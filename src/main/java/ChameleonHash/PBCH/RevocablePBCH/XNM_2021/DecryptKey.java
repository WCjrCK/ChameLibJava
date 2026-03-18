package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import ChameleonHash.CH.CHET.Components.SecretKey;
import utils.ElementCounter;

public class DecryptKey extends ChameleonHash.PBCH.RevocablePBCH.Components.DecryptKey<Info> {
    SecretKey CHET_sk;
    Encryption.ABE.RevocableABE.XNM_2021.DecryptKey RABE_dk;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
