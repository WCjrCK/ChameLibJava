package ChameleonHash.PBCH.RevocablePBCH.TMM_2022;

import utils.ElementCounter;

public class Policy extends ChameleonHash.PBCH.RevocablePBCH.Components.Policy {
    Encryption.ABE.RevocableABE.TMM_2022.Policy RABE_P;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
