package ChameleonHash.CH.CHET.BC_CDK_2017;

import utils.ElementCounter;

public class SecretKey extends ChameleonHash.CH.Components.SecretKey {
    protected ChameleonHash.CH.Components.SecretKey ch_sk;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

