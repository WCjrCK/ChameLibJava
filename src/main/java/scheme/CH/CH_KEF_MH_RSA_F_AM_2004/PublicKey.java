package scheme.CH.CH_KEF_MH_RSA_F_AM_2004;

import java.math.BigInteger;

public class PublicKey {
    public BigInteger n, e;

    public void CopyFrom(AE.RSA.PublicKey pk) {
        n = pk.N;
        e = pk.e;
    }
}
