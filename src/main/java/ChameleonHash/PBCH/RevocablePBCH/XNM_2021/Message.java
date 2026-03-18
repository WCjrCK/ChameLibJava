package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import utils.ElementCounter;

public class Message extends ChameleonHash.PBCH.RevocablePBCH.Components.Message {
    ChameleonHash.CH.CHET.Components.Message CHET_m;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
