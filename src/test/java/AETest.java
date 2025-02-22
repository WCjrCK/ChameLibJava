import AE.RSA.Native;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AETest {
    @DisplayName("test RSA")
    @Test
    void RSATest() {
        Native.PublicKey pk = new Native.PublicKey();
        Native.SecretKey sk = new Native.SecretKey();
        Native.KeyGen(pk, sk);
        BigInteger m1 = BigInteger.probablePrime(1024, new Random());
        BigInteger m2 = BigInteger.probablePrime(1024, new Random());
        assertTrue(m1.compareTo(m2) != 0, "m1 != m2");
        BigInteger c1 = Native.Encrypt(m1, pk);
        BigInteger c2 = Native.Encrypt(m2, pk);
        assertTrue(c1.compareTo(c2) != 0, "c1 != c2");
        BigInteger m1p = Native.Decrypt(c1, pk, sk);
        BigInteger m2p = Native.Decrypt(c2, pk, sk);
        assertTrue(m1p.compareTo(m2p) != 0, "m1p != m2p");
        assertEquals(0, m1p.compareTo(m1), "m1 != m1p");
        assertEquals(0, m2p.compareTo(m2), "m2 != m2p");
    }
}
