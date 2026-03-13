package scheme.IBCH.ZSS_2003;

import EllipticCurve.Curve.CurveGroup;
import scheme.Config;
import scheme.IBCH.IBCH;
import scheme.Scheme;

/*
 * ID-Based Chameleon Hashes from Bilinear Pairings
 * P4. 4.1 Scheme 1
 */

public class S1 extends Scheme implements IBCH {
    @Override
    public final scheme.IBCH.Components.PublicParam createPublicParam(Config config) {
        return new PublicParam(config);
    }

    private void Setup(
            PublicParam pp,
            MasterSecretKey msk
    ) {
        msk.s = pp.curve.createPoint(CurveGroup.Zp);
        pp.P = pp.curve.createPoint(CurveGroup.G2);
        pp.P_pub = pp.P.mulZn(msk.s);
    }

    @Override
    public void Setup(
            scheme.IBCH.Components.PublicParam pp,
            scheme.IBCH.Components.MasterSecretKey msk
    ) {
        if(!(pp instanceof PublicParam)) throw new IllegalArgumentException("公共参数不适配当前方案");
        if(!(msk instanceof MasterSecretKey)) throw new IllegalArgumentException("主密钥不适配当前方案");
        Setup((PublicParam) pp, (MasterSecretKey) msk);
    }

    private void KeyGen(
            SecretKey sk,
            PublicParam pp,
            MasterSecretKey msk,
            Identity ID
    ) {
        sk.S_ID = pp.H0(ID.ID).mulZn(msk.s);
    }

    @Override
    public void KeyGen(
            scheme.IBCH.Components.SecretKey sk,
            scheme.IBCH.Components.PublicParam pp,
            scheme.IBCH.Components.MasterSecretKey msk,
            scheme.IBCH.Components.Identity ID
    ) {
        if(!(sk instanceof SecretKey)) throw new IllegalArgumentException("密钥不适配当前方案");
        if(!(pp instanceof PublicParam)) throw new IllegalArgumentException("公共参数不适配当前方案");
        if(!(msk instanceof MasterSecretKey)) throw new IllegalArgumentException("主密钥不适配当前方案");
        if(!(ID instanceof Identity)) throw new IllegalArgumentException("身份标识不适配当前方案");
        KeyGen((SecretKey) sk, (PublicParam) pp, (MasterSecretKey) msk, (Identity) ID);
    }

    public void CalHash(HashValue h, PublicParam pp, Identity ID, Message m, Randomness r) {
        h.h = pp.curve.Pairing(r.R, pp.P).mul(pp.curve.Pairing(pp.H0(ID.ID).mulZn(pp.H1(m.m)), pp.P_pub));
    }

    public void Hash(HashValue h, Randomness r, PublicParam pp, Identity ID, Message m) {
        r.R = pp.curve.createPoint(CurveGroup.G1);
        CalHash(h, pp, ID, m, r);
    }

    @Override
    public void Hash(
            scheme.IBCH.Components.HashValue h,
            scheme.IBCH.Components.Randomness r,
            scheme.IBCH.Components.PublicParam pp,
            scheme.IBCH.Components.Identity ID,
            scheme.IBCH.Components.Message m
    ) {
        if(!(h instanceof HashValue)) throw new IllegalArgumentException("哈希值不适配当前方案");
        if(!(r instanceof Randomness)) throw new IllegalArgumentException("随机值不适配当前方案");
        if(!(pp instanceof PublicParam)) throw new IllegalArgumentException("公共参数不适配当前方案");
        if(!(ID instanceof Identity)) throw new IllegalArgumentException("身份标识不适配当前方案");
        if(!(m instanceof Message)) throw new IllegalArgumentException("消息不适配当前方案");
        Hash((HashValue) h, (Randomness) r, (PublicParam) pp, (Identity) ID, (Message) m);
    }

    public boolean Verify(PublicParam pp, Identity ID, Message m, HashValue h, Randomness r) {
        HashValue tmp = new HashValue();
        CalHash(tmp, pp, ID, m, r);
        return tmp.isEqual(h);
    }

    @Override
    public boolean Verify(
            scheme.IBCH.Components.PublicParam pp,
            scheme.IBCH.Components.Identity ID,
            scheme.IBCH.Components.Message m,
            scheme.IBCH.Components.HashValue h,
            scheme.IBCH.Components.Randomness r
    ) {
        if(!(pp instanceof PublicParam)) throw new IllegalArgumentException("公共参数不适配当前方案");
        if(!(ID instanceof Identity)) throw new IllegalArgumentException("身份标识不适配当前方案");
        if(!(m instanceof Message)) throw new IllegalArgumentException("消息不适配当前方案");
        if(!(h instanceof HashValue)) throw new IllegalArgumentException("哈希值不适配当前方案");
        if(!(r instanceof Randomness)) throw new IllegalArgumentException("随机值不适配当前方案");
        return Verify((PublicParam) pp, (Identity) ID, (Message) m, (HashValue) h, (Randomness) r);
    }

    public void Collision(Randomness r_p, PublicParam pp, SecretKey sk, Message m, Randomness r, Message m_p) {
        r_p.R = sk.S_ID.mulZn(pp.H1(m.m).sub(pp.H1(m_p.m))).add(r.R);
    }

    @Override
    public void Collision (
            scheme.IBCH.Components.Randomness r_p,
            scheme.IBCH.Components.PublicParam pp,
            scheme.IBCH.Components.Identity ID,
            scheme.IBCH.Components.SecretKey sk,
            scheme.IBCH.Components.Message m,
            scheme.IBCH.Components.HashValue h,
            scheme.IBCH.Components.Randomness r,
            scheme.IBCH.Components.Message m_p
    ) {
        if(!(r_p instanceof Randomness)) throw new IllegalArgumentException("新随机值不适配当前方案");
        if(!(pp instanceof PublicParam)) throw new IllegalArgumentException("公共参数不适配当前方案");
        if(!(ID instanceof Identity)) throw new IllegalArgumentException("身份标识不适配当前方案");
        if(!(sk instanceof SecretKey)) throw new IllegalArgumentException("密钥不适配当前方案");
        if(!(m instanceof Message)) throw new IllegalArgumentException("消息不适配当前方案");
        if(!(h instanceof HashValue)) throw new IllegalArgumentException("哈希值不适配当前方案");
        if(!(r instanceof Randomness)) throw new IllegalArgumentException("随机值不适配当前方案");
        if(!(m_p instanceof Message)) throw new IllegalArgumentException("新消息不适配当前方案");
        if(!Verify((PublicParam) pp, (Identity) ID, (Message) m, (HashValue) h, (Randomness) r)) throw new IllegalArgumentException("参数有误，哈希值与原消息不对应");
        Collision((Randomness) r_p, (PublicParam) pp, (SecretKey) sk, (Message) m, (Randomness) r, (Message) m_p);
    }
}
