package scheme.IBCH.LJF_2025;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.AdditivePoint;
import scheme.IBCH.IBCH;

import java.util.Map;

/*
 * Identity-Based Chameleon Hashes in the Standard Model for Mobile Devices
 * P6. V. PROPOSED IB-CH SCHEME WITHOUT KEY EXPOSURE
 */

public class Scheme extends scheme.Scheme implements IBCH {
    @Override
    public final scheme.IBCH.Components.PublicParam createPublicParam(CurveName curveName, Map<String, Object> params) {
        return new PublicParam(curveName, params);
    }

    private void Setup(
            PublicParam pp,
            MasterSecretKey msk
    ) {
        msk.alpha = pp.curve.createPoint(CurveGroup.Zp);
        msk.beta = pp.curve.createPoint(CurveGroup.Zp);
        pp.g = pp.curve.createPoint(CurveGroup.G1);
        pp.g_1 = pp.g.pow(msk.alpha);
        pp.g_2 = pp.g.pow(msk.beta);
        pp.h_2 = pp.curve.createPoint(CurveGroup.G1);
        pp.u_2 = pp.h_2.pow(msk.alpha);
        pp.egg = pp.curve.Pairing(pp.g, pp.g);
        pp.eg_2g = pp.curve.Pairing(pp.g_2, pp.g);
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
        sk.td_1 = pp.curve.createPoint(CurveGroup.Zp);
        sk.td_2 = pp.g.pow(msk.beta.sub(sk.td_1).mulZn(msk.alpha.sub(ID.ID).invZn()));
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
        h.h = pp.eg_2g.pow(m.m).mul(pp.egg.pow(r.r_1)).mul(pp.curve.Pairing(r.r_2, pp.g_1.mul(pp.g.pow(ID.ID.neg()))));
    }

    public void Hash(HashValue h, Randomness r, PublicParam pp, Identity ID, Message m) {
        r.r_1 = pp.curve.createPoint(CurveGroup.Zp);
        r.r_2 = pp.curve.createPoint(CurveGroup.G1);
        r.r_3 = pp.curve.createPoint(CurveGroup.G1);
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

    public void Collision(Randomness r_p, SecretKey sk, Message m, Randomness r, Message m_p) {
        AdditivePoint delta_m = m.m.sub(m_p.m);
        r_p.r_1 = r.r_1.add(sk.td_1.mulZn(delta_m));
        r_p.r_2 = r.r_2.mul(sk.td_2.pow(delta_m));
    }

    @Override
    public void Collision(
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
        Collision((Randomness) r_p, (SecretKey) sk, (Message) m, (Randomness) r, (Message) m_p);
    }
}
