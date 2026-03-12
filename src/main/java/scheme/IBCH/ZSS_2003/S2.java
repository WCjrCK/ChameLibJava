package scheme.IBCH.ZSS_2003;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Curve.CurveName;
import scheme.IBCH.IBCH;

import java.util.Map;

/*
 * ID-Based Chameleon Hashes from Bilinear Pairings
 * P4. 4.2 Scheme 2
 */

public class S2 extends IBCH {
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
        msk.s = pp.curve.createPoint(CurveGroup.Zp);
        pp.P = pp.curve.createPoint(CurveGroup.G1);
        pp.P_pub = pp.P.mulZn(msk.s);
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
        sk.S_ID = pp.H0(ID.ID).mulZn(msk.s);
        sk.S_ID = pp.P.mulZn(msk.s.add(pp.H1(ID.ID)).invZn());
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
        h.h = pp.curve.Pairing(pp.P, pp.P).mul(pp.curve.Pairing(pp.P_pub.add(pp.P.mulZn(pp.H1(ID.ID))), r.R)).pow(pp.H1(m.m));
    }

    public void Hash(HashValue h, Randomness r, PublicParam pp, Identity ID, Message m) {
        r.R = pp.curve.createPoint(CurveGroup.G1);
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

    public void Col(Randomness r_p, PublicParam pp, SecretKey sk, Message m, Randomness r, Message m_p) {
        r_p.R = sk.S_ID.mulZn(pp.H1(m.m).sub(pp.H1(m_p.m))).add(r.R.mulZn(pp.H1(m.m))).mulZn(pp.H1(m_p.m).invZn());
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
        Col((Randomness) r_p, (PublicParam) pp, (SecretKey) sk, (Message) m, (Randomness) r, (Message) m_p);
    }
}
