package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import utils.ElementCounter;

public class State extends ChameleonHash.PBCH.RevocablePBCH.Components.State {
    Encryption.ABE.RevocableABE.XNM_2021.State RABE_st;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
