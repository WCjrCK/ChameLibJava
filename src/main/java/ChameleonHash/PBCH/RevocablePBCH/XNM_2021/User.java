package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import utils.ElementCounter;

public class User
        extends ChameleonHash.PBCH.RevocablePBCH.Components.User<
        PublicParam, MasterPublicKey, PublicKey, SecretKey, Identity, Attributes, Info, Policy, Message, HashValue, Randomness> {
    Encryption.ABE.RevocableABE.XNM_2021.User RABE_user;
    private final Scheme core = new Scheme();

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, MasterPublicKey mpk, Message m, Policy P, Info info) {
        core.Hash(h, r, pp, mpk, pk, id, m, P, info);
    }

    @Override
    public boolean Verify(PublicParam pp, MasterPublicKey mpk, Message m, HashValue h, Randomness r) {
        return core.Verify(pp, mpk, pk, m, h, r);
    }

    @Override
    public void Collision(Randomness r_p, PublicParam pp, MasterPublicKey mpk, Message m, HashValue h, Randomness r, Message m_p) {
        core.Collision(r_p, pp, mpk, pk, sk, m, h, r, m_p);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
