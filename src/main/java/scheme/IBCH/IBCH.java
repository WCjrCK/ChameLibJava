package scheme.IBCH;

import scheme.Components.*;
import scheme.Scheme;

public abstract class IBCH extends Scheme {
    public abstract void Setup(PublicParam pp, MasterSecretKey msk);

    public abstract void KeyGen(SecretKey sk, PublicParam pp, MasterSecretKey msk, Identity ID);

    public abstract void Hash(HashValue h, Randomness r, PublicParam pp, Identity ID, Message m);

    public abstract boolean Ver(PublicParam pp, Identity ID, Message m, HashValue h, Randomness r);

    public abstract void Col(Randomness r_p, PublicParam pp, Identity ID, SecretKey sk, Message m, HashValue h, Randomness r, Message m_p);
}
