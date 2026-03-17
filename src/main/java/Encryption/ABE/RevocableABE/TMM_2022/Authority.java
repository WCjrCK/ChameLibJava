package Encryption.ABE.RevocableABE.TMM_2022;

import utils.ElementCounter;

public class Authority extends Encryption.ABE.RevocableABE.Components.Authority<PublicParam, MasterPublicKey, MasterSecretKey, State, Revocated, UpdateKey, Info, User> {
    @Override
    public void Setup(MasterPublicKey mpk, PublicParam pp) {
        (new Core()).Setup(mpk, msk, pp);
    }

    @Override
    public void KeyGen(User user, PublicParam pp, MasterPublicKey mpk) {
        (new Core()).KeyGen(user, pp, mpk, msk, st);
    }

    @Override
    public void KeyUpdate(PublicParam pp, MasterPublicKey mpk, Info info) {
        (new Core()).KeyUpdate(uk, pp, mpk, st, rl, info);
    }

    @Override
    public void DecryptKeyGen(User user, PublicParam pp, MasterPublicKey mpk) {
        (new Core()).DecryptKeyGen(user.dk, pp, mpk, msk, st, rl, uk, user.sk);
    }

    @Override
    public void Revoke(PublicParam pp, MasterPublicKey mpk, User user, Info info) {
        (new Core()).Revoke(rl, user, info);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
