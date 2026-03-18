package ChameleonHash.CH.CHET.BC_CDK_2017;

import utils.ElementCounter;

public class PublicKey extends ChameleonHash.CH.CHET.Components.PublicKey {
    protected ChameleonHash.CH.BaseCH.Components.PublicKey ch_pk;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

