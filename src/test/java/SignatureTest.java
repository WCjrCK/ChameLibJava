import Signature.BLS.PBC;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

public class SignatureTest {
    @BeforeEach
    void initTest() {
        InitialLib();
    }

    @DisplayName("test BLS")
    @Nested
    class BLSTest {
        @DisplayName("test PBC impl")
        @ParameterizedTest(name = "test curve {0} swap_G1G2 {1}")
        @MethodSource("ABETest#GetPBCInvert")
        void JPBCTest(curve.PBC curve, boolean swap_G1G2) {
            Signature.BLS.PBC scheme = new Signature.BLS.PBC();
            PBC.PublicParam SP = new PBC.PublicParam(curve, swap_G1G2);
            PBC.PublicKey pk1 = new PBC.PublicKey();
            PBC.PublicKey pk2 = new PBC.PublicKey();
            PBC.SecretKey sk1 = new PBC.SecretKey();
            PBC.SecretKey sk2 = new PBC.SecretKey();
            scheme.KeyGen(pk1, sk1, SP);
            scheme.KeyGen(pk2, sk2, SP);
            String m1 = "WCjrCK";
            String m2 = "123";
            PBC.Signature s1 = new PBC.Signature();
            PBC.Signature s2 = new PBC.Signature();

            scheme.Sign(s1, sk1, SP, m1);
            scheme.Sign(s2, sk2, SP, m2);

            assertFalse(s1.isEqual(s2), "s1 != s2");

            assertTrue(scheme.Verify(SP, pk1, s1, m1), "valid sign(m1)");
            assertTrue(scheme.Verify(SP, pk2, s2, m2), "valid sign(m2)");

            assertFalse(scheme.Verify(SP, pk1, s2, m1), "sign(m1) != s2");
            assertFalse(scheme.Verify(SP, pk2, s1, m1), "sign(pk2, m1) != s1");
        }
    }
}
