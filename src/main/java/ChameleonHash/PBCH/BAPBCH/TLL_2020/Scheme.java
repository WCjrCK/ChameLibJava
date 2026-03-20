package ChameleonHash.PBCH.BAPBCH.TLL_2020;

import ChameleonHash.Interface.BAPBCH;
import ChameleonHash.PBCH.PBCH;
import ChameleonHash.PBCH.PBCHConfig;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.BaseABE.FAME.PlainText;

import java.util.Arrays;

public class Scheme extends PBCH
        implements BAPBCH<PublicParam, MasterPublicKey, MasterSecretKey, Policy, User, Message, HashValue, Randomness> {
    @Override
    public PublicParam createPublicParam(PBCHConfig config) {
        return new PublicParam(config);
    }

    @Override
    public void Setup(PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk) {
        Scalar d_1 = pp.curve.getRandomScalar();
        Scalar d_2 = pp.curve.getRandomScalar();
        Scalar d_3 = pp.curve.getRandomScalar();

        msk.alpha = pp.curve.getRandomScalar();
        msk.beta = pp.curve.getRandomScalar();
        msk.z_i = new Scalar[pp.ID_LEN];
        for(int i = 0; i < pp.ID_LEN; ++i) msk.z_i[i] = pp.curve.getRandomScalar();

        pp.FAME.Setup(mpk.FAME_mpk, msk.FAME_msk, pp.FAME_pp, d_1, d_2, d_3, msk.alpha);
        mpk.g_i = new MultivePoint[pp.ID_LEN];
        for(int i = 0; i < pp.ID_LEN; ++i) mpk.g_i[i] = mpk.FAME_mpk.g.pow(msk.z_i[i]);
        mpk.g_alpha_i = new MultivePoint[pp.ID_LEN];
        for(int i = 0; i < pp.ID_LEN; ++i) mpk.g_alpha_i[i] = mpk.g_i[i].pow(msk.alpha);
        mpk.h_i = new MultivePoint[pp.ID_LEN];
        for(int i = 0; i < pp.ID_LEN; ++i) mpk.h_i[i] = mpk.FAME_mpk.h.pow(msk.z_i[i]);

        mpk.g_alpha = mpk.FAME_mpk.g.pow(msk.alpha);
        mpk.h_d_alpha = mpk.FAME_mpk.h.pow(d_1.add(d_2).add(d_3).div(msk.alpha));
        mpk.h_1_alpha = mpk.FAME_mpk.h.ext(msk.alpha);
        mpk.h_beta_alpha = mpk.FAME_mpk.h.pow(msk.beta.div(msk.alpha));

        msk.sk_ch = pp.curve.getRandomScalar();
        mpk.pk_ch = mpk.FAME_mpk.h.pow(msk.sk_ch);
    }

    @Override
    public void AssignUser(User user, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk) {
        user.ID_hat = mpk.FAME_mpk.g;
        user.ID_hat_h = mpk.FAME_mpk.h;
        for(int i = 0;i < user.ID.length;++i) {
            user.ID_hat = user.ID_hat.mul(mpk.g_i[mpk.g_i.length - i - 1].pow(user.ID[i]));
            user.ID_hat_h = user.ID_hat_h.mul(mpk.h_i[mpk.g_i.length - i - 1].pow(user.ID[i]));
        }
        user.ID_hat_alpha = user.ID_hat_h.pow(msk.alpha);
    }

    @Override
    public void KeyGen(User user, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk) {
        Scalar r_1 = pp.curve.getRandomScalar();
        Scalar r_2 = pp.curve.getRandomScalar();
        Scalar r = r_1.add(r_2);
        Scalar R = pp.curve.getRandomScalar();
        pp.FAME.KeyGen(user.sk.FAME_sk, pp.FAME_pp, mpk.FAME_mpk, msk.FAME_msk, user.S.A, r_1, r_2, msk.alpha);
        user.sk.FAME_sk.sk_0[2] = mpk.FAME_mpk.h.pow(r.div(msk.alpha));
        user.sk.sk_0_g[0] = mpk.FAME_mpk.g.ext(msk.alpha);
        user.sk.sk_0_g[1] = mpk.FAME_mpk.g.pow(r.div(msk.alpha));
        user.sk.sk_0_g[2] = mpk.FAME_mpk.g.pow(R);

        user.sk.sk_1 = msk.FAME_msk.g_d1.mul(msk.FAME_msk.g_d2).mul(msk.FAME_msk.g_d3).mul(user.ID_hat.pow(msk.alpha.mul(r))).mul(mpk.FAME_mpk.g.pow(msk.beta.mul(R)));
        r = r.mul(msk.alpha);
        user.sk.sk_2 = new MultivePoint[mpk.g_i.length - user.ID.length];
        for(int i = 0;i < user.sk.sk_2.length;++i) user.sk.sk_2[i] = mpk.g_i[user.sk.sk_2.length - i - 1].pow(r);
        user.sk.sk_ch = msk.sk_ch;
    }

    private void GenCipher(Randomness r, PublicParam pp, MasterPublicKey mpk, User user, Policy P, Scalar r_, byte[] R_) {
        Scalar s_1 = pp.curve.getRandomScalar();
        Scalar s_2 = pp.curve.getRandomScalar();
        Scalar s = s_1.add(s_2);
        r.p = mpk.pk_ch.pow(r_);

        PlainText FAME_pt = pp.FAME_pp.createPlainText("");
        FAME_pt.m = pp.curve.getOne(CurveGroup.GT);

        pp.FAME.Encrypt(r.FAME_ct, pp.FAME_pp, mpk.FAME_mpk, P.P, FAME_pt, s_1, s_2);
        r.FAME_ct.ct_0[2] = mpk.h_1_alpha.pow(s);
        r.ct_0_4 = mpk.h_beta_alpha.pow(s);

        r.ct = r.FAME_ct.ct_p.toBytes();
        r.FAME_ct.ct_p = pp.curve.getOne(CurveGroup.GT);
        byte[] tmp = r_.toBytes();
        for(int i = 0;i < tmp.length;++i) r.ct[i] ^= tmp[i];


        r.ct_p = pp.H2(pp.curve.Pairing(mpk.FAME_mpk.g, mpk.h_d_alpha).pow(s).toString()).toBytes();
        for(int i = 0;i < R_.length;++i) r.ct_p[i] ^= R_[i];

        r.ct_1 = user.ID_hat_alpha.pow(s);
        r.ct_2 = user.ID_hat_h.pow(s);
        r.ct_3 = r.ct_1.pow(s);

        Scalar esk = pp.curve.getRandomScalar();
        r.epk = mpk.FAME_mpk.g.pow(esk);
        r.c = mpk.FAME_mpk.h.pow(s.add(pp.H2(Arrays.toString(R_))));
        r.sigma = esk.add(s.mul(pp.H2(String.format("%s|%s", r.epk, r.c))));

        // ct_2 ^ alpha ?= ct_1
    }

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, MasterPublicKey mpk, User user, Message m, Policy P) {
        h.owner_ID = Arrays.copyOf(user.ID, user.ID.length);

        Scalar r_ = pp.curve.getRandomScalar();

        byte[] R_ = new byte[r_.toBytes().length / 2];
        pp.rand.nextBytes(R_);

        GenCipher(r, pp, mpk, user, P, r_, R_);

        h.h_p = mpk.FAME_mpk.h.pow(pp.H2(Arrays.toString(R_)));

        h.b = r.p.mul(h.h_p.pow(m.m));
    }

    @Override
    public boolean Verify(PublicParam pp, MasterPublicKey mpk, Message m, HashValue h, Randomness r) {
        return h.b.isEqual(r.p.mul(h.h_p.pow(m.m))) && pp.curve.Pairing(mpk.g_alpha, r.ct_2).pow(r.sigma).isEqual(pp.curve.Pairing(r.epk, r.ct_1).mul(pp.curve.Pairing(mpk.FAME_mpk.g, r.ct_3).pow(pp.H2(String.format("%s|%s", r.epk, r.c)))));
    }

    @Override
    public void Collision(Randomness r_p, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, User user, Message m, Policy P, HashValue h, Randomness r, Message m_p) {
//        if(!Verify(pp, mpk, m, h, r)) throw new RuntimeException("wrong hash");

        User moder_p = pp.createUser(user.ID.length);
        moder_p.CopyFrom(user);
        moder_p.sk.delegate_z = pp.curve.getZeroScalar();

        for(int i = moder_p.ID.length;i < h.owner_ID.length;++i)
            if(!moder_p.delegate(pp, mpk, msk, h.owner_ID[i])) throw new RuntimeException("派生用户私钥失败");

        byte[] R_ = pp.H2(pp.curve.Pairing(moder_p.sk.sk_1, r.FAME_ct.ct_0[2]).div(pp.curve.Pairing(moder_p.sk.sk_0_g[1], r.ct_1).mul(pp.curve.Pairing(moder_p.sk.sk_0_g[2], r.ct_0_4))).toString()).toBytes();
        for(int i = 0;i < R_.length;++i) R_[i] ^= r.ct_p[i];

        boolean tag = true;
        for(int i = R_.length / 2;i < R_.length;++i) if(R_[i] != 0) {
            tag = false;
            break;
        }
        if(!tag) throw new RuntimeException("unable to adapt");

        R_ = Arrays.copyOf(R_, R_.length / 2);

        PlainText pt_RABE = pp.FAME_pp.createPlainText("");
        pp.FAME.Decrypt(pt_RABE, pp.FAME_pp, moder_p.sk.FAME_sk, r.FAME_ct, P.P);

        byte[] r_ = pt_RABE.m.inv().toBytes();
        for(int i = 0;i < r_.length;++i) r_[i] ^= r.ct[i];

        Scalar r_p_ = pp.curve.createScalarFromBytes(r_).add(m.m.sub(m_p.m).mul(pp.H2(Arrays.toString(R_)).div(moder_p.sk.sk_ch)));

        GenCipher(r_p, pp, mpk, moder_p, P, r_p_, R_);
    }


}
