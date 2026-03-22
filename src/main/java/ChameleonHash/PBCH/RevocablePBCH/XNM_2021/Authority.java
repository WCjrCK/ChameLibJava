package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import utils.ElementCounter;

public class Authority extends ChameleonHash.PBCH.RevocablePBCH.Components.Authority<
        PublicParam, MasterPublicKey, MasterSecretKey, State, Revocated, UpdateKey, Info, User> {
    @Override
    public void Setup(MasterPublicKey mpk, PublicParam pp) {
        (new Scheme()).Setup(pp, mpk, msk);
    }

    @Override
    public void KeyGen(User user, PublicParam pp, MasterPublicKey mpk) {

    }

    @Override
    public void KeyUpdate(PublicParam pp, MasterPublicKey mpk, Info info) {

    }

    @Override
    public void DecryptKeyGen(User user, PublicParam pp, MasterPublicKey mpk) {

    }

    @Override
    public void Revoke(PublicParam pp, MasterPublicKey mpk, User user, Info info) {

    }

    @Override
    public ElementCounter TheoSize() {
        return null;
    }
}
