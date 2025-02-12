import AE.RSA.PublicKey;
import AE.RSA.RSA;
import AE.RSA.SecretKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AETest {
    @DisplayName("test RSA")
    @Nested
    class RSATest {
        @DisplayName("test")
        @Test
        void rsaTest() {
            PublicKey pk = new PublicKey();
            SecretKey sk = new SecretKey();
            RSA.KeyGen(pk, sk);
            BigInteger m1 = BigInteger.probablePrime(1024, new Random());
            BigInteger m2 = BigInteger.probablePrime(1024, new Random());
            assertTrue(m1.compareTo(m2) != 0, "m1 != m2");
            BigInteger c1 = RSA.Encrypt(m1, pk);
            BigInteger c2 = RSA.Encrypt(m2, pk);
            assertTrue(c1.compareTo(c2) != 0, "c1 != c2");
            BigInteger m1p = RSA.Decrypt(c1, pk, sk);
            BigInteger m2p = RSA.Decrypt(c2, pk, sk);
            assertTrue(m1p.compareTo(m2p) != 0, "m1p != m2p");
            assertEquals(0, m1p.compareTo(m1), "m1 != m1p");
            assertEquals(0, m2p.compareTo(m2), "m2 != m2p");

        }
    }
}
