package ChameleonHash.CH.CHET.BC_CDK_2017;

import utils.ElementCounter;

public class Message extends ChameleonHash.CH.CHET.Components.Message {
    protected ChameleonHash.CH.BaseCH.Components.Message m;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

