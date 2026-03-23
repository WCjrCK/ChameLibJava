package ChameleonHash.PBCH.RevocablePBCH.TMM_2022;

import utils.ElementCounter;

public class State extends ChameleonHash.PBCH.RevocablePBCH.Components.State {
    Encryption.ABE.RevocableABE.TMM_2022.State RABE_st;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
