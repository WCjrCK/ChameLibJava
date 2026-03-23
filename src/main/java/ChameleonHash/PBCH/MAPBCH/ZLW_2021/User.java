package ChameleonHash.PBCH.MAPBCH.ZLW_2021;

import utils.ElementCounter;

public class User extends ChameleonHash.PBCH.MAPBCH.Components.User<
        PublicParam, Authority, Attribute, Policy, Message, HashValue, Randomness> {
    protected Encryption.ABE.MAABE.Components.User MAABE_user;
    private final Scheme scheme = new Scheme();

    protected User() {}

    @Override
    public void KeyGen(PublicParam pp, Authority auth) {
        MAABE_user.KeyGen(pp.MAABE_pp, auth.MAABE_auth);
    }

    @Override
    public void AddAttr(Attribute attr) {
        MAABE_user.AddAttr(attr.MAABE_attr);
    }

    @Override
    public void Setup(PublicParam pp) {
        scheme.UserSetup(this, pp);
    }

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, Policy P, Message m) {
        scheme.Hash(h, r, pp, new Identity(MAABE_user.id), new PublicKeyGroup(MAABE_user.pkg), P, m);
    }

    @Override
    public boolean Verify(PublicParam pp, Message m, HashValue h, Randomness r) {
        return scheme.Verify(pp, new Identity(MAABE_user.id), new PublicKeyGroup(MAABE_user.pkg), m, h, r);
    }

    @Override
    public void Collision(Randomness r_p, PublicParam pp, Message m, HashValue h, Randomness r, Message m_p) {
        scheme.Collision(r_p, pp, new Identity(MAABE_user.id), new PublicKeyGroup(MAABE_user.pkg), new SecretKeyGroup(MAABE_user.skg), m, h, r, m_p);
    }

    @Override
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
