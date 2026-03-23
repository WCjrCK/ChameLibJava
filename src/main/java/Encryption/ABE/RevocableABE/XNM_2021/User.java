package Encryption.ABE.RevocableABE.XNM_2021;

import utils.ElementCounter;

public class User extends Encryption.ABE.RevocableABE.Components.User<
        PublicParam, MasterPublicKey, SecretKey, Info, Identity, Policy, PlainText, CipherText> {
    public User(Identity id) {
        super(id);
    }

    @Override
    public void Encrypt(CipherText ct, PublicParam pp, MasterPublicKey mpk, Policy P, PlainText pt, Info info) {
        (new Core()).Encrypt(ct, pp, mpk, P, pt, info);
    }

    @Override
    public void Decrypt(PlainText pt, PublicParam pp, MasterPublicKey mpk, CipherText ct) {
        (new Core()).Decrypt(pt, pp, sk, ct);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}