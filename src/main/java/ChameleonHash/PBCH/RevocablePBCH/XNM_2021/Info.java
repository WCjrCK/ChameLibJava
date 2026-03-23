package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import utils.ElementCounter;

import java.util.HashMap;

public class Info extends ChameleonHash.PBCH.RevocablePBCH.Components.Info {
    Encryption.ABE.RevocableABE.XNM_2021.Info RABE_info;

    public Info() {}

    public Info(Encryption.ABE.RevocableABE.XNM_2021.Info info) {
        RABE_info = info;
    }

    @Override
    public void setValue(HashMap<String, Object> map) {
        RABE_info.setValue(map);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
