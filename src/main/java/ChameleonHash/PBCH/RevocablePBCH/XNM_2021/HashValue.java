package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import Encryption.ABE.RevocableABE.XNM_2021.CipherText;
import utils.ElementCounter;

public class HashValue extends ChameleonHash.PBCH.RevocablePBCH.Components.HashValue<HashValue> {
    ChameleonHash.CH.CHET.Components.HashValue CHET_h;
    CipherText RABE_ct;
    Encryption.SE.Components.CipherText SE_ct;

    @Override
    public boolean isEqual(HashValue other) {
        return CHET_h.isEqual(other.CHET_h) && RABE_ct.isEqual(other.RABE_ct) && SE_ct.isEqual(other.SE_ct);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
