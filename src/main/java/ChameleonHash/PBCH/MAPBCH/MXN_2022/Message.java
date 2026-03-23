package ChameleonHash.PBCH.MAPBCH.MXN_2022;

import utils.ElementCounter;

public class Message extends ChameleonHash.PBCH.MAPBCH.Components.Message {
    protected ChameleonHash.CH.CHET.Components.Message CHET_m;

    @Override
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
