package scheme.IBCH.LSX_2022;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.AdditivePoint;
import scheme.IBCH.IBCH;

import java.util.Map;

/*
 * Efficient Identity-Based Chameleon Hash For Mobile Devices
 * P2. 3. PROPOSED EFFICIENT IB-CH
 */

public class Scheme extends IBCH {
    @Override
    public final scheme.Components.PublicParam createPublicParam(CurveName curveName, Map<String, Object> params) {
        return new PublicParam(curveName, params);
    }

    @Override
    public final scheme.Components.MasterSecretKey createMasterSecretKey() {
        return new MasterSecretKey();
    }

    @Override
    public final scheme.Components.SecretKey createSecretKey() {
        return new SecretKey();
    }

    @Override
    public final scheme.Components.HashValue createHashValue() {
        return new HashValue();
    }

    @Override
    public final scheme.Components.Randomness createRandomness() {
        return new Randomness();
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
        pp.egg = pp.curve.Pairing(pp.g, pp.g);
        pp.eg_2g = pp.curve.Pairing(pp.g_2, pp.g);
    }

    @Override
    public void Setup(
            scheme.Components.PublicParam pp,
            scheme.Components.MasterSecretKey msk
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
            scheme.Components.SecretKey sk,
            scheme.Components.PublicParam pp,
            scheme.Components.MasterSecretKey msk,
            scheme.Components.Identity ID
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
        CalHash(h, pp, ID, m, r);
    }

    @Override
    public void Hash(
            scheme.Components.HashValue h,
            scheme.Components.Randomness r,
            scheme.Components.PublicParam pp,
            scheme.Components.Identity ID,
            scheme.Components.Message m
    ) {
        if(!(h instanceof HashValue)) throw new IllegalArgumentException("哈希值不适配当前方案");
        if(!(r instanceof Randomness)) throw new IllegalArgumentException("随机值不适配当前方案");
        if(!(pp instanceof PublicParam)) throw new IllegalArgumentException("公共参数不适配当前方案");
        if(!(ID instanceof Identity)) throw new IllegalArgumentException("身份标识不适配当前方案");
        if(!(m instanceof Message)) throw new IllegalArgumentException("消息不适配当前方案");
        Hash((HashValue) h, (Randomness) r, (PublicParam) pp, (Identity) ID, (Message) m);
    }

    public boolean Ver(PublicParam pp, Identity ID, Message m, HashValue h, Randomness r) {
        HashValue tmp = new HashValue();
        CalHash(tmp, pp, ID, m, r);
        return tmp.isEqual(h);
    }

    @Override
    public boolean Ver(
            scheme.Components.PublicParam pp,
            scheme.Components.Identity ID,
            scheme.Components.Message m,
            scheme.Components.HashValue h,
            scheme.Components.Randomness r
    ) {
        if(!(pp instanceof PublicParam)) throw new IllegalArgumentException("公共参数不适配当前方案");
        if(!(ID instanceof Identity)) throw new IllegalArgumentException("身份标识不适配当前方案");
        if(!(m instanceof Message)) throw new IllegalArgumentException("消息不适配当前方案");
        if(!(h instanceof HashValue)) throw new IllegalArgumentException("哈希值不适配当前方案");
        if(!(r instanceof Randomness)) throw new IllegalArgumentException("随机值不适配当前方案");
        return Ver((PublicParam) pp, (Identity) ID, (Message) m, (HashValue) h, (Randomness) r);
    }

    public void Col(Randomness r_p, SecretKey sk, Message m, Randomness r, Message m_p) {
        AdditivePoint delta_m = m.m.sub(m_p.m);
        r_p.r_1 = r.r_1.add(sk.td_1.mulZn(delta_m));
        r_p.r_2 = r.r_2.mul(sk.td_2.pow(delta_m));
    }

    @Override
    public void Col(
            scheme.Components.Randomness r_p,
            scheme.Components.PublicParam pp,
            scheme.Components.Identity ID,
            scheme.Components.SecretKey sk,
            scheme.Components.Message m,
            scheme.Components.HashValue h,
            scheme.Components.Randomness r,
            scheme.Components.Message m_p
    ) {
        if(!(r_p instanceof Randomness)) throw new IllegalArgumentException("新随机值不适配当前方案");
        if(!(pp instanceof PublicParam)) throw new IllegalArgumentException("公共参数不适配当前方案");
        if(!(ID instanceof Identity)) throw new IllegalArgumentException("身份标识不适配当前方案");
        if(!(sk instanceof SecretKey)) throw new IllegalArgumentException("密钥不适配当前方案");
        if(!(m instanceof Message)) throw new IllegalArgumentException("消息不适配当前方案");
        if(!(h instanceof HashValue)) throw new IllegalArgumentException("哈希值不适配当前方案");
        if(!(r instanceof Randomness)) throw new IllegalArgumentException("随机值不适配当前方案");
        if(!(m_p instanceof Message)) throw new IllegalArgumentException("新消息不适配当前方案");
        if(!Ver((PublicParam) pp, (Identity) ID, (Message) m, (HashValue) h, (Randomness) r)) throw new IllegalArgumentException("参数有误，哈希值与原消息不对应");
        Col((Randomness) r_p, (SecretKey) sk, (Message) m, (Randomness) r, (Message) m_p);
    }
}
