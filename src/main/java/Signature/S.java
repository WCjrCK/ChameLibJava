package Signature;

import EllipticCurve.Curve.CurveName;
import Signature.Components.*;

import java.util.Map;

public abstract class S {
    public abstract PublicParam createPublicParam(CurveName curveName, Map<String, Object> params);

    public abstract SecretKey createSecretKey();

    public abstract Message createMessage(String m);

    public abstract PublicKey createPublicKey();

    public abstract SignValue createSignValue();

    public abstract void Setup(PublicParam pp);

    public abstract void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp);

    public abstract void Sign(SignValue s, PublicParam pp, SecretKey sk, Message m);

    public abstract boolean Verify(PublicParam pp, PublicKey pk, SignValue s, Message m);
}
