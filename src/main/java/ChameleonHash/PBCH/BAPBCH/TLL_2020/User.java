package ChameleonHash.PBCH.BAPBCH.TLL_2020;

import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

import java.util.Arrays;

public class User extends ChameleonHash.PBCH.BAPBCH.Components.User<Attributes, SecretKey> {
    protected MultivePoint ID_hat_alpha;
    protected MultivePoint ID_hat, ID_hat_h;
    protected Scalar[] ID;

    protected User() {}

    protected void CopyFrom(User u) {
        sk.CopyFrom(u.sk);
        ID_hat_alpha = u.ID_hat_alpha.copy();
        ID_hat = u.ID_hat.copy();
        ID_hat_h = u.ID_hat_h.copy();
        ID = Arrays.copyOf(u.ID, u.ID.length);
    }

    public boolean delegate(PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, Scalar I_i_1) {
        ID = Arrays.copyOf(ID, ID.length + 1);
        ID[ID.length - 1] = I_i_1;
        ID_hat = ID_hat.mul(mpk.g_i[mpk.g_i.length - ID.length].pow(I_i_1));
        ID_hat_h = ID_hat_h.mul(mpk.h_i[mpk.h_i.length - ID.length].pow(I_i_1));
        ID_hat_alpha = ID_hat_alpha.mul(mpk.h_i[mpk.h_i.length - ID.length].pow(I_i_1.mul(msk.alpha)));
        return sk.delegate(pp, mpk, msk, ID_hat.pow(msk.alpha), I_i_1);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
