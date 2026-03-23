package ChameleonHash.PBCH.MAPBCH.MXN_2022;

import Encryption.SE.Components.CipherText;
import utils.ElementCounter;

public class HashValue extends ChameleonHash.PBCH.MAPBCH.Components.HashValue<HashValue> {
    protected ChameleonHash.CH.CHET.Components.HashValue CHET_h;
    protected CipherText SE_ct;
    protected Encryption.ABE.MAABE.RW_2015.CipherText MAABE_ct;

    @Override
    public boolean isEqual(HashValue other) {
        return CHET_h.isEqual(other.CHET_h)
                && SE_ct.isEqual(other.SE_ct)
                && MAABE_ct.isEqual(other.MAABE_ct);
    }

    @Override
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
