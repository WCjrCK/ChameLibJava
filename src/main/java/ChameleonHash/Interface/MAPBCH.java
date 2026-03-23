package ChameleonHash.Interface;

import ChameleonHash.PBCH.MAPBCH.Components.*;
import ChameleonHash.PBCH.PBCHConfig;

public interface MAPBCH<
        PP extends PublicParam,
        AUTH extends Authority,
        U extends User,
        PKG extends PublicKeyGroup,
        PK extends PublicKey,
        SKG extends SecretKeyGroup,
        SK extends SecretKey,
        ID extends Identity,
        AT extends Attribute,
        P extends Policy,
        M extends Message,
        H extends HashValue,
        R extends Randomness
        > {
    PP createPublicParam(PBCHConfig config);

    void Setup(PP pp);

    void AuthSetup(AUTH auth, PP pp);

    void UserSetup(U user, PP pp);

    void KeyGen(PK pk, SK sk, PP pp, AUTH auth, ID id, AT attr);

    void Hash(H h, R r, PP pp, ID id, PKG pkg, P P, M m);

    boolean Verify(PP pp, ID id, PKG pkg, M m, H h, R r);

    void Collision(R r_p, PP pp, ID id, PKG pkg, SKG skg, M m, H h, R r, M m_p);
}
