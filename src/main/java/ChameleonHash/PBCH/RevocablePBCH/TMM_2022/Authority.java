package ChameleonHash.PBCH.RevocablePBCH.TMM_2022;

import utils.ElementCounter;

public class Authority extends ChameleonHash.PBCH.RevocablePBCH.Components.Authority<
        PublicParam, MasterPublicKey, MasterSecretKey, State, Info, User> {
    @Override
    public void Setup(MasterPublicKey mpk, PublicParam pp) {
        (new Scheme()).Setup(pp, mpk, msk);
    }

    @Override
    public void KeyGen(User user, PublicParam pp, MasterPublicKey mpk) {
        (new Scheme()).KeyGen(user.pk, user.sk, pp, mpk, msk, st, user.id, user.S);
    }

    @Override
    public void KeyUpdate(PublicParam pp, MasterPublicKey mpk, Info info) {
        (new Scheme()).KeyUpdate(st, pp, mpk, msk, info);
    }

    @Override
    public void DecryptKeyGen(User user, PublicParam pp, MasterPublicKey mpk) {
        (new Scheme()).DecryptKeyGen(user.sk, pp, mpk, msk, st);
    }

    @Override
    public void Revoke(PublicParam pp, MasterPublicKey mpk, User user, Info info) {
        (new Scheme()).Revoke(st, pp, mpk, msk, user.id, info);
    }

    @Override
    public ElementCounter TheoSize() {
        return null;
    }
}
