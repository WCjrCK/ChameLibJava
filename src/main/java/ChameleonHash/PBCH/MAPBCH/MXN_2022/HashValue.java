package ChameleonHash.PBCH.MAPBCH.MXN_2022;

import utils.ElementCounter;

public class HashValue extends ChameleonHash.PBCH.MAPBCH.Components.HashValue<HashValue> {
    protected ChameleonHash.CH.CHET.Components.HashValue CHET_h;
    protected Encryption.ABE.MAABE.Components.CipherText MAABE_ct;

    @Override
    public boolean isEqual(HashValue other) {
        return CHET_h.isEqual(other.CHET_h) && MAABE_ct.isEqual(other.MAABE_ct);
    }

    @Override
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
