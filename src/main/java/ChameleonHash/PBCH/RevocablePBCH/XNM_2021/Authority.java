package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import utils.ElementCounter;

public class Authority extends ChameleonHash.PBCH.RevocablePBCH.Components.Authority<
        PublicParam, MasterPublicKey, MasterSecretKey, State, Info, User> {
    private final Scheme core = new Scheme();
    
    @Override
    public void Setup(MasterPublicKey mpk, PublicParam pp) {
        core.Setup(pp, mpk, msk);
    }

    @Override
    public void KeyGen(User user, PublicParam pp, MasterPublicKey mpk) {
        core.KeyGen(user.pk, user.sk, pp, mpk, msk, st, user.id, user.S);
    }

    @Override
    public void KeyUpdate(PublicParam pp, MasterPublicKey mpk, Info info) {
        core.KeyUpdate(st, pp, mpk, msk, info);
    }

    @Override
    public void DecryptKeyGen(User user, PublicParam pp, MasterPublicKey mpk) {
        core.DecryptKeyGen(user.sk, pp, mpk, msk, st);
    }

    @Override
    public void Revoke(PublicParam pp, MasterPublicKey mpk, User user, Info info) {
        core.Revoke(st, pp, mpk, msk, user.id, info);
    }

    @Override
    public ElementCounter TheoSize() {
        return null;
    }
}
