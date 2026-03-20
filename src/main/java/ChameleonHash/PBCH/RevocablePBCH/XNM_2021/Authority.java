package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import utils.ElementCounter;

public class Authority extends ChameleonHash.PBCH.RevocablePBCH.Components.Authority<
        PublicParam, MasterPublicKey, MasterSecretKey, State, Revocated, UpdateKey, Info, User> {
    @Override
    public void Setup(MasterPublicKey masterPublicKey, PublicParam publicParam) {

    }

    @Override
    public void KeyGen(User user, PublicParam publicParam, MasterPublicKey masterPublicKey) {

    }

    @Override
    public void KeyUpdate(PublicParam publicParam, MasterPublicKey masterPublicKey, Info info) {

    }

    @Override
    public void DecryptKeyGen(User user, PublicParam publicParam, MasterPublicKey masterPublicKey) {

    }

    @Override
    public void Revoke(PublicParam publicParam, MasterPublicKey masterPublicKey, User user, Info info) {

    }

    @Override
    public ElementCounter TheoSize() {
        return null;
    }
}
