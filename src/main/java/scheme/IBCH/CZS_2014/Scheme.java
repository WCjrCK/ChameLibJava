package scheme.IBCH.CZS_2014;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import EllipticCurve.Point.AdditivePoint;
import scheme.IBCH.IBCH;

import java.util.Map;

/*
 * Identity-based chameleon hashing and signatures without key exposure
 * P6. 4.1. The proposed identity-based chameleon hash scheme
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
        msk.x = pp.curve.createPoint(CurveGroup.Zp);
        pp.P = pp.curve.createPoint(CurveGroup.G1);
        pp.P_pub = pp.P.mulZn(msk.x);
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
        sk.S_ID = pp.H_p(ID.L).mulZn(msk.x);
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
        h.h = r.r_1.add(pp.H(ID.L).mulZn(m.m));
    }

    public void Hash(HashValue h, Randomness r, PublicParam pp, Identity ID, Message m) {
        AdditivePoint a = pp.curve.createPoint(CurveGroup.Zp);
        r.r_1 = pp.P.mulZn(a);
        r.r_2 = pp.curve.Pairing(pp.P_pub.mulZn(a), pp.H_p(ID.L));
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

    public void Col(Randomness r_p, PublicParam pp, Identity ID, SecretKey sk, Message m, Randomness r, Message m_p) {
        AdditivePoint HL = pp.H(ID.L);
        r_p.r_1 = r.r_1.add(HL.mulZn(m.m.sub(m_p.m)));
        r_p.r_2 = r.r_2.mul(pp.curve.Pairing(HL, sk.S_ID).pow(m.m.sub(m_p.m)));
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
        Col((Randomness) r_p, (PublicParam) pp, (Identity) ID, (SecretKey) sk, (Message) m, (Randomness) r, (Message) m_p);
    }
}
