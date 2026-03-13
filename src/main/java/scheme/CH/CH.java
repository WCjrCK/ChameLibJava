package scheme.CH;

import EllipticCurve.Curve.CurveName;
import scheme.CH.Components.*;

import java.util.Map;

public interface CH {
    PublicParam createPublicParam(CurveName curveName, Map<String, Object> params);

    void Setup(PublicParam pp);

    void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp);

    void Hash(HashValue h, Randomness r, PublicParam pp, Message m);

    boolean Verify(PublicParam pp, Message m, HashValue h, Randomness r);

    void Collision(Randomness r_p, PublicParam pp, SecretKey sk, Message m, HashValue h, Randomness r, Message m_p);
}
