package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import utils.ElementCounter;

public class User
        extends ChameleonHash.PBCH.RevocablePBCH.Components.User<
        PublicParam, MasterPublicKey, PublicKey, SecretKey, DecryptKey, Identity, Attributes, Info, Policy, Message, HashValue, Randomness> {
    Encryption.ABE.RevocableABE.XNM_2021.User RABE_user;

    protected User(Identity identity) {
        super(identity);
    }

    @Override
    public void Hash(HashValue hashValue, Randomness randomness, PublicParam publicParam, MasterPublicKey masterPublicKey, Identity identity, PublicKey publicKey, Message message, Policy P, Info info) {

    }

    @Override
    public boolean Verify(PublicParam publicParam, MasterPublicKey masterPublicKey, PublicKey publicKey, Message message, HashValue hashValue, Randomness randomness) {
        return false;
    }

    @Override
    public void Collision(Randomness r_p, PublicParam publicParam, MasterPublicKey masterPublicKey, PublicKey publicKey, Message message, Policy P, HashValue hashValue, Randomness randomness, Message m_p) {

    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
