package scheme.IBCH;

import EllipticCurve.Curve.CurveName;
import scheme.Components.*;
import scheme.Scheme;

import java.util.Map;

public abstract class IBCH extends Scheme {
    public abstract PublicParam createPublicParam(CurveName curveName, Map<String, Object> params);

    public abstract MasterSecretKey createMasterSecretKey();

    public abstract SecretKey createSecretKey();

    public abstract Identity createIdentity(String ID);

    public abstract Message createMessage(String msg);

    public abstract HashValue createHashValue();

    public abstract Randomness createRandomness();

    public abstract void Setup(PublicParam pp, MasterSecretKey msk);

    public abstract void KeyGen(SecretKey sk, PublicParam pp, MasterSecretKey msk, Identity ID);

    public abstract void Hash(HashValue h, Randomness r, PublicParam pp, Identity ID, Message m);

    public abstract boolean Ver(PublicParam pp, Identity ID, Message m, HashValue h, Randomness r);

    public abstract void Col(Randomness r_p, PublicParam pp, Identity ID, SecretKey sk, Message m, HashValue h, Randomness r, Message m_p);
}
