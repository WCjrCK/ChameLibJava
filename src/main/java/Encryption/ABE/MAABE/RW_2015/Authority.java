package Encryption.ABE.MAABE.RW_2015;

import utils.ElementCounter;

public class Authority extends Encryption.ABE.MAABE.Components.Authority<
        PublicParam, AuthPublicKey, AuthSecretKey,
        PublicKey, SecretKey, Identity, Attribute> {
    private final Core core = new Core();

    @Override
    public void AddAttr(Attribute attr) {
        controled_attr.add(attr);
    }

    public void Setup(PublicParam pp) {
        core.AuthSetup(this, pp);
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp, Identity id, Attribute attr) {
        core.KeyGen(pk, sk, pp, this, id, attr);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
