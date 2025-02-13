import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import scheme.CH.CH_KEF_NoMH_AM_2004.*;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.func.InitialLib;

public class CHTest {
    @BeforeAll
    static void initTest() {
        InitialLib();
    }

    @DisplayName("test CH_KEF_NoMH_AM_2004")
    @Test
    void CH_KEF_NoMH_AM_2004_Test() {
        Random rand = new Random();
        CH_KEF_NoMH_AM_2004 scheme = new CH_KEF_NoMH_AM_2004();
        PublicKey pk = new PublicKey();
        SecretKey sk = new SecretKey();
        scheme.KeyGen(pk, sk, 512);
        BigInteger m1 = new BigInteger(256, rand);
        BigInteger m2 = new BigInteger(256, rand);
        assertTrue(m1.compareTo(m2) != 0, "m1 != m2");
        HashValue h1 = new HashValue();
        HashValue h2 = new HashValue();
        Randomness r1 = new Randomness();
        Randomness r2 = new Randomness();
        Randomness r2_p = new Randomness();
        scheme.Hash(h1, r1, pk, m1);
        assertTrue(scheme.Check(h1, r1, pk, m1), "H(m1) invalid");
        scheme.Hash(h2, r2, pk, m2);
        assertTrue(scheme.Check(h2, r2, pk, m2), "H(m2) invalid");

        scheme.Adapt(r2_p, h1, pk, sk, m2);
        assertTrue(scheme.Check(h1, r2_p, pk, m2), "Adapt(m2) invalid");
    }
}
