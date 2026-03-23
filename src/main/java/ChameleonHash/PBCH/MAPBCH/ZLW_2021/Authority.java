package ChameleonHash.PBCH.MAPBCH.ZLW_2021;

import utils.ElementCounter;

public class Authority extends ChameleonHash.PBCH.MAPBCH.Components.Authority<PublicParam, PublicKey, SecretKey, Identity, Attribute> {
    protected Encryption.ABE.MAABE.Components.Authority MAABE_auth;
    private final Scheme scheme = new Scheme();

    @Override
    public void AddAttr(Attribute attr) {
        MAABE_auth.AddAttr(attr.MAABE_attr);
    }

    @Override
    public void Setup(PublicParam pp) {
        scheme.AuthSetup(this, pp);
    }

    @Override
    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp, Identity id, Attribute attr) {
        scheme.KeyGen(pk, sk, pp, this, id, attr);
    }

    @Override
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
