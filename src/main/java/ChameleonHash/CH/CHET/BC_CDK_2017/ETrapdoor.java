package ChameleonHash.CH.CHET.BC_CDK_2017;

import ChameleonHash.CH.BaseCH.Components.SecretKey;
import utils.ElementCounter;

public class ETrapdoor extends ChameleonHash.CH.CHET.Components.ETrapdoor {
    protected SecretKey ch_sk;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
