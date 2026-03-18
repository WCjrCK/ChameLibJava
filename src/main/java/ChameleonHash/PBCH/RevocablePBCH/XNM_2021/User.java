package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import utils.ElementCounter;

public class User extends ChameleonHash.PBCH.RevocablePBCH.Components.User<Attributes, SecretKey> {
    Encryption.ABE.RevocableABE.XNM_2021.User RABE_user;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
