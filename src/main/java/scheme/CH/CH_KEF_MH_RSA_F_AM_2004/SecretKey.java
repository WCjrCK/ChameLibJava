package scheme.CH.CH_KEF_MH_RSA_F_AM_2004;

import java.math.BigInteger;

public class SecretKey {
    public BigInteger p, q, d;

    public void CopyFrom(AE.RSA.SecretKey sk) {
        p = sk.p;
        q = sk.q;
        d = sk.d;
    }
}
