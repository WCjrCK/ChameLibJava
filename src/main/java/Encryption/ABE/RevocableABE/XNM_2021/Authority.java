package Encryption.ABE.RevocableABE.XNM_2021;

import utils.ElementCounter;

public class Authority extends Encryption.ABE.RevocableABE.Components.Authority<PublicParam, MasterPublicKey, MasterSecretKey, State, Info, User> {
    private final Core core = new Core();
    
    @Override
    public void Setup(MasterPublicKey mpk, PublicParam pp) {
        core.Setup(mpk, msk, pp);
    }

    @Override
    public void KeyGen(User user, PublicParam pp, MasterPublicKey mpk) {
        core.KeyGen(user.sk, pp, mpk, msk, st, user.id, user.S);
    }

    @Override
    public void KeyUpdate(PublicParam pp, MasterPublicKey mpk, Info info) {
        core.KeyUpdate(st, pp, mpk, info);
    }

    @Override
    public void DecryptKeyGen(User user, PublicParam pp, MasterPublicKey mpk) {
        core.DecryptKeyGen(user.sk, pp, mpk, msk, st);
    }

    @Override
    public void Revoke(PublicParam pp, MasterPublicKey mpk, User user, Info info) {
        core.Revoke(st, user.id, info);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
