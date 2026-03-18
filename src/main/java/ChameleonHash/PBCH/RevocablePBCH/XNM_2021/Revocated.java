package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import utils.ElementCounter;

public class Revocated extends ChameleonHash.PBCH.RevocablePBCH.Components.Revocated {
    protected Encryption.ABE.RevocableABE.XNM_2021.Revocated RABE_rl;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
