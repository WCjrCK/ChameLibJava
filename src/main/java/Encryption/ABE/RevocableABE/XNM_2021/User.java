package Encryption.ABE.RevocableABE.XNM_2021;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class User extends Encryption.ABE.RevocableABE.Components.User<PublicParam, MasterPublicKey, SecretKey, DecryptKey, Info, Policy, PlainText, CipherText> {
    protected final MultivePoint id;

    public User(MultivePoint id) {
        this.id = id;
    }

    @Override
    public int hashCode() {
        return id.toString().hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof User) {
            return id.isEqual(((User) obj).id);
        }
        return false;
    }

    @Override
    public void Encrypt(CipherText ct, PublicParam pp, MasterPublicKey mpk, Policy P, PlainText pt, Info info) {
        (new Core()).Encrypt(ct, pp, mpk, P, pt, info);
    }

    @Override
    public void Decrypt(PlainText pt, PublicParam pp, MasterPublicKey mpk, Policy P, CipherText ct) {
        (new Core()).Decrypt(pt, pp, dk, ct, P);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}