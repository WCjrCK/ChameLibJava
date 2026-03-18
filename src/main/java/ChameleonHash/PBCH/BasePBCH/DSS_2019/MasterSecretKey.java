package ChameleonHash.PBCH.BasePBCH.DSS_2019;

import ChameleonHash.CH.CHET.Components.SecretKey;
import utils.ElementCounter;

public class MasterSecretKey extends ChameleonHash.PBCH.BasePBCH.Components.MasterSecretKey {
    protected SecretKey CHET_sk;
    protected Encryption.ABE.BaseABE.FAME.MasterSecretKey FAME_msk;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
