package ChameleonHash.CH.CHET.BC_CDK_2017;

import utils.ElementCounter;

public class Message extends ChameleonHash.CH.Components.Message {
    protected ChameleonHash.CH.Components.Message m;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

