package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import utils.ElementCounter;

public class User
        extends ChameleonHash.PBCH.RevocablePBCH.Components.User<
        PublicParam, MasterPublicKey, SecretKey, Identity, Attributes, Info, Policy, Message, HashValue, Randomness> {
    Encryption.ABE.RevocableABE.XNM_2021.User RABE_user;

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, MasterPublicKey mpk, Message m, Policy P, Info info) {
        (new Scheme()).Hash(h, r, pp, mpk, id, m, P, info);
    }

    @Override
    public boolean Verify(PublicParam pp, MasterPublicKey mpk, Message m, HashValue h, Randomness r) {
        return (new Scheme()).Verify(pp, mpk, m, h, r);
    }

    @Override
    public void Collision(Randomness r_p, PublicParam pp, MasterPublicKey mpk, Message m, HashValue h, Randomness r, Message m_p) {
        (new Scheme()).Collision(r_p, pp, mpk, sk, m, h, r, m_p);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
