package Signature.BLS;

import EllipticCurve.Curve.CurveGroup;
import Signature.Config;
import Signature.S;

public class Scheme extends S {
    @Override
    public final PublicParam createPublicParam(Config config) {
        return new PublicParam(config);
    }

    private void Setup(PublicParam pp) {
        pp.g = pp.curve.createPoint(CurveGroup.G2);
    }

    @Override
    public final void Setup(Signature.Components.PublicParam pp) {
        if(!(pp instanceof PublicParam)) throw new IllegalArgumentException("公共参数不适配当前方案");
        Setup((PublicParam) pp);
    }

    private void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        sk.alpha = pp.curve.createScalar();
        pk.h = pp.g.pow(sk.alpha);
    }

    @Override
    public final void KeyGen(Signature.Components.PublicKey pk, Signature.Components.SecretKey sk, Signature.Components.PublicParam pp) {
        if(!(pk instanceof PublicKey)) throw new IllegalArgumentException("公钥不适配当前方案");
        if(!(sk instanceof SecretKey)) throw new IllegalArgumentException("密钥不适配当前方案");
        if(!(pp instanceof PublicParam)) throw new IllegalArgumentException("公共参数不适配当前方案");
        KeyGen((PublicKey) pk, (SecretKey) sk, (PublicParam) pp);
    }

    private void Sign(SignValue s, PublicParam pp, SecretKey sk, Message m) {
        s.sigma_m = pp.H(m.m).pow(sk.alpha);
    }
    @Override
    public final void Sign(Signature.Components.SignValue s, Signature.Components.PublicParam pp, Signature.Components.SecretKey sk, Signature.Components.Message m) {
        if(!(s instanceof SignValue)) throw new IllegalArgumentException("签名不适配当前方案");
        if(!(pp instanceof PublicParam)) throw new IllegalArgumentException("公共参数不适配当前方案");
        if(!(sk instanceof SecretKey)) throw new IllegalArgumentException("密钥不适配当前方案");
        if(!(m instanceof Message)) throw new IllegalArgumentException("消息不适配当前方案");
        Sign((SignValue) s, (PublicParam) pp, (SecretKey) sk, (Message) m);
    }

    private boolean Verify(PublicParam pp, PublicKey pk, SignValue s, Message m) {
        return pp.curve.Pairing(s.sigma_m, pp.g).isEqual(pp.curve.Pairing(pp.H(m.m), pk.h));
    }
    @Override
    public final boolean Verify(Signature.Components.PublicParam pp, Signature.Components.PublicKey pk, Signature.Components.SignValue s, Signature.Components.Message m) {
        if(!(pp instanceof PublicParam)) throw new IllegalArgumentException("公共参数不适配当前方案");
        if(!(pk instanceof PublicKey)) throw new IllegalArgumentException("公钥不适配当前方案");
        if(!(s instanceof SignValue)) throw new IllegalArgumentException("签名不适配当前方案");
        if(!(m instanceof Message)) throw new IllegalArgumentException("消息不适配当前方案");
        return Verify((PublicParam) pp, (PublicKey) pk, (SignValue) s, (Message) m);
    }
}
