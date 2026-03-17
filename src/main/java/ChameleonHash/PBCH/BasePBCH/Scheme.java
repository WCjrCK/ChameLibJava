package ChameleonHash.PBCH.BasePBCH;

import ChameleonHash.Interface.BasePBCH;
import ChameleonHash.PBCH.Components.*;
import ChameleonHash.PBCH.PBCH;
import ChameleonHash.PBCH.PBCHConfig;

public abstract class Scheme<
        PP extends PublicParam<MPK, MSK, SK, P, A, M, H, R>,
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        P extends Policy,
        A extends Attributes,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > extends PBCH implements BasePBCH<PP, MPK, MSK, SK, P, A, M, H, R> {
    public abstract PP createPublicParam(PBCHConfig config);

    public abstract void Setup(PP pp, MPK mpk, MSK msk);

    public abstract void KeyGen(SK sk, PP pp, MPK mpk, MSK msk, A S);

    public abstract void Hash(H h, R r, PP pp, MPK mpk, M m, P P);

    public abstract boolean Verify(PP pp, MPK mpk, M m, H h, R r);

    public abstract void Collision(R r_p, PP pp, MPK mpk, SK sk, M m, P P, H h, R r, M m_p);
}
