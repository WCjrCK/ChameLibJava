package ChameleonHash.PBCH.BasePBCH.DSS_2019;

import Encryption.ABE.BaseABE.FAME.CipherText;
import utils.ElementCounter;

public class HashValue extends ChameleonHash.PBCH.BasePBCH.Components.HashValue<HashValue> {
    protected ChameleonHash.CH.CHET.Components.HashValue CHET_h;
    protected CipherText FAME_ct;
    protected Encryption.SE.Components.CipherText SE_ct;

    @Override
    public boolean isEqual(HashValue other) {
        return CHET_h.isEqual(other.CHET_h) && FAME_ct.isEqual(other.FAME_ct) && SE_ct.isEqual(other.SE_ct);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
