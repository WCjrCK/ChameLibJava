package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import utils.ElementCounter;

public class Policy extends ChameleonHash.PBCH.RevocablePBCH.Components.Policy {
    Encryption.ABE.RevocableABE.XNM_2021.Policy RABE_P;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
