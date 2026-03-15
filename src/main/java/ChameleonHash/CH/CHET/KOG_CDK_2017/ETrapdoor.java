package ChameleonHash.CH.CHET.KOG_CDK_2017;

import utils.ElementCounter;

public class ETrapdoor extends ChameleonHash.CH.CHET.Comoponents.ETrapdoor {
    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
