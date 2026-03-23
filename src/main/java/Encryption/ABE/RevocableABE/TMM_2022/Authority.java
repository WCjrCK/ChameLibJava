package Encryption.ABE.RevocableABE.TMM_2022;

import utils.ElementCounter;

public class Authority extends Encryption.ABE.RevocableABE.Components.Authority<PublicParam, MasterPublicKey, MasterSecretKey, State, Info, User> {
    @Override
    public void Setup(MasterPublicKey mpk, PublicParam pp) {
        (new Core()).Setup(mpk, msk, pp);
    }

    @Override
    public void KeyGen(User user, PublicParam pp, MasterPublicKey mpk) {
        (new Core()).KeyGen(user.sk, pp, mpk, msk, st, user.id, user.S);
    }

    @Override
    public void KeyUpdate(PublicParam pp, MasterPublicKey mpk, Info info) {
        (new Core()).KeyUpdate(st, pp, mpk, info);
    }

    @Override
    public void DecryptKeyGen(User user, PublicParam pp, MasterPublicKey mpk) {
        (new Core()).DecryptKeyGen(user.sk, st);
    }

    @Override
    public void Revoke(PublicParam pp, MasterPublicKey mpk, User user, Info info) {
        (new Core()).Revoke(st, user.id, info);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
