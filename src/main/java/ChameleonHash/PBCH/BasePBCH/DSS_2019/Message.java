package ChameleonHash.PBCH.BasePBCH.DSS_2019;

import utils.ElementCounter;

public class Message extends ChameleonHash.PBCH.Components.Message {
    ChameleonHash.CH.Components.Message CHET_m;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
