package ChameleonHash.CH.CHET.BC_CDK_2017;

import utils.ElementCounter;

public class SecretKey extends ChameleonHash.CH.CHET.Components.SecretKey<SecretKey> {
    protected ChameleonHash.CH.BaseCH.Components.SecretKey ch_sk;

    @Override
    public void CopyFrom(SecretKey o) {
        ch_sk.CopyFrom(o.ch_sk);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

