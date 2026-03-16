package ChameleonHash.CH.CHET.BC_CDK_2017;

import ChameleonHash.CH.Components.PublicKey;
import utils.ElementCounter;

public class HashValue extends ChameleonHash.CH.Components.HashValue<HashValue> {
    protected ChameleonHash.CH.Components.HashValue h_1, h_2;
    protected PublicKey ch_pk;

    @Override
    public final boolean isEqual(HashValue other) {
        return h_1.isEqual(other.h_1) && h_2.isEqual(other.h_2);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

