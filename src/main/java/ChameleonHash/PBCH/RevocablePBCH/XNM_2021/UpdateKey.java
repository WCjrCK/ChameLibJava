package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import utils.ElementCounter;

public class UpdateKey extends ChameleonHash.PBCH.RevocablePBCH.Components.UpdateKey<Info> {
    Encryption.ABE.RevocableABE.XNM_2021.UpdateKey RABE_uk;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
