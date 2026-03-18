package ChameleonHash.PBCH.BAPBCH.TLL_2020;

import utils.ElementCounter;

public class Policy extends ChameleonHash.PBCH.BasePBCH.Components.Policy {
    protected Encryption.ABE.BaseABE.FAME.Policy P;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
