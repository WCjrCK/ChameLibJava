package ChameleonHash.PBCH.MAPBCH.MXN_2022;

import utils.ElementCounter;

public class User extends ChameleonHash.PBCH.MAPBCH.Components.User<
        PublicParam, Authority, Attribute, Policy, Message, HashValue, Randomness> {
    protected final String gid;
    protected Encryption.ABE.MAABE.RW_2015.User MAABE_user;
    protected Signature.Components.SignValue DS_sigma_gid;
    private final Scheme scheme = new Scheme();

    protected User(String gid) {
        this.gid = gid;
    }

    @Override
    public void KeyGen(PublicParam pp, Authority auth) {
        Identity id = new Identity(gid, MAABE_user.id, DS_sigma_gid);
        for (Encryption.ABE.MAABE.RW_2015.Attribute controlledAttr : auth.MAABE_auth.controled_attr) {
            Attribute attr = new Attribute();
            attr.MAABE_attr = controlledAttr;

            PublicKey pk = pp.createPublicKey();
            SecretKey sk = pp.createSecretKey();
            scheme.KeyGen(pk, sk, pp, auth, id, attr);
            MAABE_user.pkg.AddPK(pk.MAABE_pk, attr.MAABE_attr);
            if (MAABE_user.owned_attr.contains(attr.MAABE_attr)) MAABE_user.skg.AddSK(sk.MAABE_sk, attr.MAABE_attr);
        }
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
        scheme.Hash(h, r, pp, new Identity(gid, MAABE_user.id, DS_sigma_gid), new PublicKeyGroup(MAABE_user.pkg), P, m);
    }

    @Override
    public boolean Verify(PublicParam pp, Message m, HashValue h, Randomness r) {
        return scheme.Verify(pp, new Identity(gid, MAABE_user.id, DS_sigma_gid), new PublicKeyGroup(MAABE_user.pkg), m, h, r);
    }

    @Override
    public void Collision(Randomness r_p, PublicParam pp, Message m, HashValue h, Randomness r, Message m_p) {
        scheme.Collision(r_p, pp, new Identity(gid, MAABE_user.id, DS_sigma_gid), new PublicKeyGroup(MAABE_user.pkg), new SecretKeyGroup(MAABE_user.skg), m, h, r, m_p);
    }

    @Override
    public ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
