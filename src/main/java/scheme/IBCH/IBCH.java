package scheme.IBCH;

import scheme.Config;
import scheme.IBCH.Components.*;

public interface IBCH {
    PublicParam createPublicParam(Config config);

    void Setup(PublicParam pp, MasterSecretKey msk);

    void KeyGen(SecretKey sk, PublicParam pp, MasterSecretKey msk, Identity ID);

    void Hash(HashValue h, Randomness r, PublicParam pp, Identity ID, Message m);

    boolean Verify(PublicParam pp, Identity ID, Message m, HashValue h, Randomness r);

    void Collision(Randomness r_p, PublicParam pp, Identity ID, SecretKey sk, Message m, HashValue h, Randomness r, Message m_p);
}
