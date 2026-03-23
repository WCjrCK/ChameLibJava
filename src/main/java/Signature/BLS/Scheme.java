package Signature.BLS;

import EllipticCurve.Curve.CurveGroup;
import Signature.S;
import Signature.SConfig;

public class Scheme extends S<PublicParam, PublicKey, SecretKey, Message, SignValue> {
    @Override
    public final PublicParam createPublicParam(SConfig config) {
        return new PublicParam(config);
    }

    @Override
    public final void Setup(PublicParam pp) {
        pp.g = pp.curve.getRandomPoint(CurveGroup.G2);
    }

    @Override
    public final void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        sk.alpha = pp.curve.getRandomScalar();
        pk.h = pp.g.pow(sk.alpha);
    }    @Override
    public final void Sign(SignValue s, PublicParam pp, SecretKey sk, Message m) {
        s.sigma_m = pp.H(m.m).pow(sk.alpha);
    }

    @Override
    public final boolean Verify(PublicParam pp, PublicKey pk, SignValue s, Message m) {
        return pp.curve.Pairing(s.sigma_m, pp.g).isEqual(pp.curve.Pairing(pp.H(m.m), pk.h));
    }
}
