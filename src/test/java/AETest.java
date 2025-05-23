import AE.RSA.Native;
import curve.Group;
import curve.MCL;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import utils.Func;

import java.math.BigInteger;
import java.util.EnumSet;
import java.util.Random;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static utils.Func.InitialLib;

public class AETest {
    public static Stream<Arguments> GetPBCCartesianProduct() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a -> EnumSet.allOf(Group.class).stream().flatMap(b -> Stream.of(Arguments.of(a, b))));
    }

    @BeforeEach
    void initTest() {
        InitialLib();
    }

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

    @DisplayName("test paper 《Redactable Blockchain or Rewriting History in Bitcoin and Friends》")
    @Nested
    class RedactableBlockchainorRewritingHistoryinBitcoinandFriendsTest {
        @DisplayName("test PKE_CCA_AMV_2017")
        @Nested
        class PKE_CCA_AMV_2017_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} group {1}")
            @MethodSource("AETest#GetPBCCartesianProduct")
            void JPBCTest(curve.PBC curve, Group group) {
                AE.PKE_CCA_AMV_2017.PBC scheme = new AE.PKE_CCA_AMV_2017.PBC();
                AE.PKE_CCA_AMV_2017.PBC.PublicParam pp = new AE.PKE_CCA_AMV_2017.PBC.PublicParam();
                scheme.SetUp(pp, curve, group);
                AE.PKE_CCA_AMV_2017.PBC.PublicKey pk1 = new AE.PKE_CCA_AMV_2017.PBC.PublicKey();
                AE.PKE_CCA_AMV_2017.PBC.SecretKey sk1 = new AE.PKE_CCA_AMV_2017.PBC.SecretKey();
                scheme.KeyGen(pk1, sk1, pp);
                AE.PKE_CCA_AMV_2017.PBC.PublicKey pk2 = new AE.PKE_CCA_AMV_2017.PBC.PublicKey();
                AE.PKE_CCA_AMV_2017.PBC.SecretKey sk2 = new AE.PKE_CCA_AMV_2017.PBC.SecretKey();
                scheme.KeyGen(pk2, sk2, pp);

                AE.PKE_CCA_AMV_2017.PBC.PlainText pt1 = new AE.PKE_CCA_AMV_2017.PBC.PlainText();
                pt1.m = pp.GetZrElement();
                AE.PKE_CCA_AMV_2017.PBC.PlainText pt2 = new AE.PKE_CCA_AMV_2017.PBC.PlainText();
                pt2.m = pp.GetZrElement();
                AE.PKE_CCA_AMV_2017.PBC.PlainText pt_p = new AE.PKE_CCA_AMV_2017.PBC.PlainText();

                AE.PKE_CCA_AMV_2017.PBC.CipherText ct1 = new AE.PKE_CCA_AMV_2017.PBC.CipherText();
                AE.PKE_CCA_AMV_2017.PBC.CipherText ct2 = new AE.PKE_CCA_AMV_2017.PBC.CipherText();

                scheme.Encrypt(ct1, pp, pk1, pt1);
                scheme.Encrypt(ct2, pp, pk2, pt2);

                scheme.Decrypt(pt_p, pp, sk1, ct1);
                assertTrue(pt_p.isEqual(pt1), "decrypt(c1) = m1");
                assertFalse(pt_p.isEqual(pt2), "decrypt(c1) != m2");

                scheme.Decrypt(pt_p, pp, sk2, ct2);
                assertTrue(pt_p.isEqual(pt2), "decrypt(c2) = m2");
            }

            @DisplayName("test MCL impl")
            @ParameterizedTest(name = "test curve {0}")
            // BadCaseTest#MCL_Bad_Case#Case2
            @EnumSource(names = {"BN254", "BLS12_381"})
            void MCLTest(MCL curve) {
                Func.MCLInit(curve);
                {
                    AE.PKE_CCA_AMV_2017.MCL_G1 scheme = new AE.PKE_CCA_AMV_2017.MCL_G1();
                    AE.PKE_CCA_AMV_2017.MCL_G1.PublicParam pp = new AE.PKE_CCA_AMV_2017.MCL_G1.PublicParam();
                    scheme.SetUp(pp);
                    AE.PKE_CCA_AMV_2017.MCL_G1.PublicKey pk1 = new AE.PKE_CCA_AMV_2017.MCL_G1.PublicKey();
                    AE.PKE_CCA_AMV_2017.MCL_G1.SecretKey sk1 = new AE.PKE_CCA_AMV_2017.MCL_G1.SecretKey();
                    scheme.KeyGen(pk1, sk1, pp);
                    AE.PKE_CCA_AMV_2017.MCL_G1.PublicKey pk2 = new AE.PKE_CCA_AMV_2017.MCL_G1.PublicKey();
                    AE.PKE_CCA_AMV_2017.MCL_G1.SecretKey sk2 = new AE.PKE_CCA_AMV_2017.MCL_G1.SecretKey();
                    scheme.KeyGen(pk2, sk2, pp);

                    AE.PKE_CCA_AMV_2017.MCL_G1.PlainText pt1 = new AE.PKE_CCA_AMV_2017.MCL_G1.PlainText();
                    pp.GP.GetZrElement(pt1.m);
                    AE.PKE_CCA_AMV_2017.MCL_G1.PlainText pt2 = new AE.PKE_CCA_AMV_2017.MCL_G1.PlainText();
                    pp.GP.GetZrElement(pt2.m);
                    AE.PKE_CCA_AMV_2017.MCL_G1.PlainText pt_p = new AE.PKE_CCA_AMV_2017.MCL_G1.PlainText();

                    AE.PKE_CCA_AMV_2017.MCL_G1.CipherText ct1 = new AE.PKE_CCA_AMV_2017.MCL_G1.CipherText();
                    AE.PKE_CCA_AMV_2017.MCL_G1.CipherText ct2 = new AE.PKE_CCA_AMV_2017.MCL_G1.CipherText();

                    scheme.Encrypt(ct1, pp, pk1, pt1);
                    scheme.Encrypt(ct2, pp, pk2, pt2);

                    scheme.Decrypt(pt_p, pp, sk1, ct1);
                    assertTrue(pt_p.isEqual(pt1), "decrypt(c1) = m1");
                    assertFalse(pt_p.isEqual(pt2), "decrypt(c1) != m2");

                    scheme.Decrypt(pt_p, pp, sk2, ct2);
                    assertTrue(pt_p.isEqual(pt2), "decrypt(c2) = m2");
                }
                {
                    AE.PKE_CCA_AMV_2017.MCL_G2 scheme = new AE.PKE_CCA_AMV_2017.MCL_G2();
                    AE.PKE_CCA_AMV_2017.MCL_G2.PublicParam pp = new AE.PKE_CCA_AMV_2017.MCL_G2.PublicParam();
                    scheme.SetUp(pp);
                    AE.PKE_CCA_AMV_2017.MCL_G2.PublicKey pk1 = new AE.PKE_CCA_AMV_2017.MCL_G2.PublicKey();
                    AE.PKE_CCA_AMV_2017.MCL_G2.SecretKey sk1 = new AE.PKE_CCA_AMV_2017.MCL_G2.SecretKey();
                    scheme.KeyGen(pk1, sk1, pp);
                    AE.PKE_CCA_AMV_2017.MCL_G2.PublicKey pk2 = new AE.PKE_CCA_AMV_2017.MCL_G2.PublicKey();
                    AE.PKE_CCA_AMV_2017.MCL_G2.SecretKey sk2 = new AE.PKE_CCA_AMV_2017.MCL_G2.SecretKey();
                    scheme.KeyGen(pk2, sk2, pp);

                    AE.PKE_CCA_AMV_2017.MCL_G2.PlainText pt1 = new AE.PKE_CCA_AMV_2017.MCL_G2.PlainText();
                    pp.GP.GetZrElement(pt1.m);
                    AE.PKE_CCA_AMV_2017.MCL_G2.PlainText pt2 = new AE.PKE_CCA_AMV_2017.MCL_G2.PlainText();
                    pp.GP.GetZrElement(pt2.m);
                    AE.PKE_CCA_AMV_2017.MCL_G2.PlainText pt_p = new AE.PKE_CCA_AMV_2017.MCL_G2.PlainText();

                    AE.PKE_CCA_AMV_2017.MCL_G2.CipherText ct1 = new AE.PKE_CCA_AMV_2017.MCL_G2.CipherText();
                    AE.PKE_CCA_AMV_2017.MCL_G2.CipherText ct2 = new AE.PKE_CCA_AMV_2017.MCL_G2.CipherText();

                    scheme.Encrypt(ct1, pp, pk1, pt1);
                    scheme.Encrypt(ct2, pp, pk2, pt2);

                    scheme.Decrypt(pt_p, pp, sk1, ct1);
                    assertTrue(pt_p.isEqual(pt1), "decrypt(c1) = m1");
                    assertFalse(pt_p.isEqual(pt2), "decrypt(c1) != m2");

                    scheme.Decrypt(pt_p, pp, sk2, ct2);
                    assertTrue(pt_p.isEqual(pt2), "decrypt(c2) = m2");
                }
                {
                    AE.PKE_CCA_AMV_2017.MCL_GT scheme = new AE.PKE_CCA_AMV_2017.MCL_GT();
                    AE.PKE_CCA_AMV_2017.MCL_GT.PublicParam pp = new AE.PKE_CCA_AMV_2017.MCL_GT.PublicParam();
                    scheme.SetUp(pp);
                    AE.PKE_CCA_AMV_2017.MCL_GT.PublicKey pk1 = new AE.PKE_CCA_AMV_2017.MCL_GT.PublicKey();
                    AE.PKE_CCA_AMV_2017.MCL_GT.SecretKey sk1 = new AE.PKE_CCA_AMV_2017.MCL_GT.SecretKey();
                    scheme.KeyGen(pk1, sk1, pp);
                    AE.PKE_CCA_AMV_2017.MCL_GT.PublicKey pk2 = new AE.PKE_CCA_AMV_2017.MCL_GT.PublicKey();
                    AE.PKE_CCA_AMV_2017.MCL_GT.SecretKey sk2 = new AE.PKE_CCA_AMV_2017.MCL_GT.SecretKey();
                    scheme.KeyGen(pk2, sk2, pp);

                    AE.PKE_CCA_AMV_2017.MCL_GT.PlainText pt1 = new AE.PKE_CCA_AMV_2017.MCL_GT.PlainText();
                    pp.GP.GetZrElement(pt1.m);
                    AE.PKE_CCA_AMV_2017.MCL_GT.PlainText pt2 = new AE.PKE_CCA_AMV_2017.MCL_GT.PlainText();
                    pp.GP.GetZrElement(pt2.m);
                    AE.PKE_CCA_AMV_2017.MCL_GT.PlainText pt_p = new AE.PKE_CCA_AMV_2017.MCL_GT.PlainText();

                    AE.PKE_CCA_AMV_2017.MCL_GT.CipherText ct1 = new AE.PKE_CCA_AMV_2017.MCL_GT.CipherText();
                    AE.PKE_CCA_AMV_2017.MCL_GT.CipherText ct2 = new AE.PKE_CCA_AMV_2017.MCL_GT.CipherText();

                    scheme.Encrypt(ct1, pp, pk1, pt1);
                    scheme.Encrypt(ct2, pp, pk2, pt2);

                    scheme.Decrypt(pt_p, pp, sk1, ct1);
                    assertTrue(pt_p.isEqual(pt1), "decrypt(c1) = m1");
                    assertFalse(pt_p.isEqual(pt2), "decrypt(c1) != m2");

                    scheme.Decrypt(pt_p, pp, sk2, ct2);
                    assertTrue(pt_p.isEqual(pt2), "decrypt(c2) = m2");
                }
            }
        }

        @DisplayName("test PKE_CPA_AMV_2017")
        @Nested
        class PKE_CPA_AMV_2017_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} group {1}")
            @MethodSource("AETest#GetPBCCartesianProduct")
            void JPBCTest(curve.PBC curve, Group group) {
                AE.PKE_CPA_AMV_2017.PBC scheme = new AE.PKE_CPA_AMV_2017.PBC();
                AE.PKE_CPA_AMV_2017.PBC.PublicParam pp = new AE.PKE_CPA_AMV_2017.PBC.PublicParam();
                scheme.SetUp(pp, curve, group);
                AE.PKE_CPA_AMV_2017.PBC.PublicKey pk1 = new AE.PKE_CPA_AMV_2017.PBC.PublicKey();
                AE.PKE_CPA_AMV_2017.PBC.SecretKey sk1 = new AE.PKE_CPA_AMV_2017.PBC.SecretKey();
                scheme.KeyGen(pk1, sk1, pp);
                AE.PKE_CPA_AMV_2017.PBC.PublicKey pk2 = new AE.PKE_CPA_AMV_2017.PBC.PublicKey();
                AE.PKE_CPA_AMV_2017.PBC.SecretKey sk2 = new AE.PKE_CPA_AMV_2017.PBC.SecretKey();
                scheme.KeyGen(pk2, sk2, pp);

                AE.PKE_CPA_AMV_2017.PBC.PlainText pt1 = new AE.PKE_CPA_AMV_2017.PBC.PlainText();
                pt1.m = pp.GetZrElement();
                AE.PKE_CPA_AMV_2017.PBC.PlainText pt2 = new AE.PKE_CPA_AMV_2017.PBC.PlainText();
                pt2.m = pp.GetZrElement();
                AE.PKE_CPA_AMV_2017.PBC.PlainText pt_p = new AE.PKE_CPA_AMV_2017.PBC.PlainText();

                AE.PKE_CPA_AMV_2017.PBC.CipherText ct1 = new AE.PKE_CPA_AMV_2017.PBC.CipherText();
                AE.PKE_CPA_AMV_2017.PBC.CipherText ct2 = new AE.PKE_CPA_AMV_2017.PBC.CipherText();

                scheme.Encrypt(ct1, pp, pk1, pt1);
                scheme.Encrypt(ct2, pp, pk2, pt2);

                scheme.Decrypt(pt_p, pp, sk1, ct1);
                assertTrue(pt_p.isEqual(pt1), "decrypt(c1) = m1");
                assertFalse(pt_p.isEqual(pt2), "decrypt(c1) != m2");

                scheme.Decrypt(pt_p, pp, sk2, ct2);
                assertTrue(pt_p.isEqual(pt2), "decrypt(c2) = m2");
            }

            @DisplayName("test MCL impl")
            @ParameterizedTest(name = "test curve {0}")
            // BadCaseTest#MCL_Bad_Case#Case2
            @EnumSource(names = {"BN254", "BLS12_381"})
            void MCLTest(MCL curve) {
                Func.MCLInit(curve);
                {
                    AE.PKE_CPA_AMV_2017.MCL_G1 scheme = new AE.PKE_CPA_AMV_2017.MCL_G1();
                    AE.PKE_CPA_AMV_2017.MCL_G1.PublicParam pp = new AE.PKE_CPA_AMV_2017.MCL_G1.PublicParam();
                    scheme.SetUp(pp);
                    AE.PKE_CPA_AMV_2017.MCL_G1.PublicKey pk1 = new AE.PKE_CPA_AMV_2017.MCL_G1.PublicKey();
                    AE.PKE_CPA_AMV_2017.MCL_G1.SecretKey sk1 = new AE.PKE_CPA_AMV_2017.MCL_G1.SecretKey();
                    scheme.KeyGen(pk1, sk1, pp);
                    AE.PKE_CPA_AMV_2017.MCL_G1.PublicKey pk2 = new AE.PKE_CPA_AMV_2017.MCL_G1.PublicKey();
                    AE.PKE_CPA_AMV_2017.MCL_G1.SecretKey sk2 = new AE.PKE_CPA_AMV_2017.MCL_G1.SecretKey();
                    scheme.KeyGen(pk2, sk2, pp);

                    AE.PKE_CPA_AMV_2017.MCL_G1.PlainText pt1 = new AE.PKE_CPA_AMV_2017.MCL_G1.PlainText();
                    pp.GP.GetZrElement(pt1.m);
                    AE.PKE_CPA_AMV_2017.MCL_G1.PlainText pt2 = new AE.PKE_CPA_AMV_2017.MCL_G1.PlainText();
                    pp.GP.GetZrElement(pt2.m);
                    AE.PKE_CPA_AMV_2017.MCL_G1.PlainText pt_p = new AE.PKE_CPA_AMV_2017.MCL_G1.PlainText();

                    AE.PKE_CPA_AMV_2017.MCL_G1.CipherText ct1 = new AE.PKE_CPA_AMV_2017.MCL_G1.CipherText();
                    AE.PKE_CPA_AMV_2017.MCL_G1.CipherText ct2 = new AE.PKE_CPA_AMV_2017.MCL_G1.CipherText();

                    scheme.Encrypt(ct1, pp, pk1, pt1);
                    scheme.Encrypt(ct2, pp, pk2, pt2);

                    scheme.Decrypt(pt_p, pp, sk1, ct1);
                    assertTrue(pt_p.isEqual(pt1), "decrypt(c1) = m1");
                    assertFalse(pt_p.isEqual(pt2), "decrypt(c1) != m2");

                    scheme.Decrypt(pt_p, pp, sk2, ct2);
                    assertTrue(pt_p.isEqual(pt2), "decrypt(c2) = m2");
                }
                {
                    AE.PKE_CPA_AMV_2017.MCL_G1 scheme = new AE.PKE_CPA_AMV_2017.MCL_G1();
                    AE.PKE_CPA_AMV_2017.MCL_G1.PublicParam pp = new AE.PKE_CPA_AMV_2017.MCL_G1.PublicParam();
                    scheme.SetUp(pp);
                    AE.PKE_CPA_AMV_2017.MCL_G1.PublicKey pk1 = new AE.PKE_CPA_AMV_2017.MCL_G1.PublicKey();
                    AE.PKE_CPA_AMV_2017.MCL_G1.SecretKey sk1 = new AE.PKE_CPA_AMV_2017.MCL_G1.SecretKey();
                    scheme.KeyGen(pk1, sk1, pp);
                    AE.PKE_CPA_AMV_2017.MCL_G1.PublicKey pk2 = new AE.PKE_CPA_AMV_2017.MCL_G1.PublicKey();
                    AE.PKE_CPA_AMV_2017.MCL_G1.SecretKey sk2 = new AE.PKE_CPA_AMV_2017.MCL_G1.SecretKey();
                    scheme.KeyGen(pk2, sk2, pp);

                    AE.PKE_CPA_AMV_2017.MCL_G1.PlainText pt1 = new AE.PKE_CPA_AMV_2017.MCL_G1.PlainText();
                    pp.GP.GetZrElement(pt1.m);
                    AE.PKE_CPA_AMV_2017.MCL_G1.PlainText pt2 = new AE.PKE_CPA_AMV_2017.MCL_G1.PlainText();
                    pp.GP.GetZrElement(pt2.m);
                    AE.PKE_CPA_AMV_2017.MCL_G1.PlainText pt_p = new AE.PKE_CPA_AMV_2017.MCL_G1.PlainText();

                    AE.PKE_CPA_AMV_2017.MCL_G1.CipherText ct1 = new AE.PKE_CPA_AMV_2017.MCL_G1.CipherText();
                    AE.PKE_CPA_AMV_2017.MCL_G1.CipherText ct2 = new AE.PKE_CPA_AMV_2017.MCL_G1.CipherText();

                    scheme.Encrypt(ct1, pp, pk1, pt1);
                    scheme.Encrypt(ct2, pp, pk2, pt2);

                    scheme.Decrypt(pt_p, pp, sk1, ct1);
                    assertTrue(pt_p.isEqual(pt1), "decrypt(c1) = m1");
                    assertFalse(pt_p.isEqual(pt2), "decrypt(c1) != m2");

                    scheme.Decrypt(pt_p, pp, sk2, ct2);
                    assertTrue(pt_p.isEqual(pt2), "decrypt(c2) = m2");
                }
                {
                    AE.PKE_CPA_AMV_2017.MCL_GT scheme = new AE.PKE_CPA_AMV_2017.MCL_GT();
                    AE.PKE_CPA_AMV_2017.MCL_GT.PublicParam pp = new AE.PKE_CPA_AMV_2017.MCL_GT.PublicParam();
                    scheme.SetUp(pp);
                    AE.PKE_CPA_AMV_2017.MCL_GT.PublicKey pk1 = new AE.PKE_CPA_AMV_2017.MCL_GT.PublicKey();
                    AE.PKE_CPA_AMV_2017.MCL_GT.SecretKey sk1 = new AE.PKE_CPA_AMV_2017.MCL_GT.SecretKey();
                    scheme.KeyGen(pk1, sk1, pp);
                    AE.PKE_CPA_AMV_2017.MCL_GT.PublicKey pk2 = new AE.PKE_CPA_AMV_2017.MCL_GT.PublicKey();
                    AE.PKE_CPA_AMV_2017.MCL_GT.SecretKey sk2 = new AE.PKE_CPA_AMV_2017.MCL_GT.SecretKey();
                    scheme.KeyGen(pk2, sk2, pp);

                    AE.PKE_CPA_AMV_2017.MCL_GT.PlainText pt1 = new AE.PKE_CPA_AMV_2017.MCL_GT.PlainText();
                    pp.GP.GetZrElement(pt1.m);
                    AE.PKE_CPA_AMV_2017.MCL_GT.PlainText pt2 = new AE.PKE_CPA_AMV_2017.MCL_GT.PlainText();
                    pp.GP.GetZrElement(pt2.m);
                    AE.PKE_CPA_AMV_2017.MCL_GT.PlainText pt_p = new AE.PKE_CPA_AMV_2017.MCL_GT.PlainText();

                    AE.PKE_CPA_AMV_2017.MCL_GT.CipherText ct1 = new AE.PKE_CPA_AMV_2017.MCL_GT.CipherText();
                    AE.PKE_CPA_AMV_2017.MCL_GT.CipherText ct2 = new AE.PKE_CPA_AMV_2017.MCL_GT.CipherText();

                    scheme.Encrypt(ct1, pp, pk1, pt1);
                    scheme.Encrypt(ct2, pp, pk2, pt2);

                    scheme.Decrypt(pt_p, pp, sk1, ct1);
                    assertTrue(pt_p.isEqual(pt1), "decrypt(c1) = m1");
                    assertFalse(pt_p.isEqual(pt2), "decrypt(c1) != m2");

                    scheme.Decrypt(pt_p, pp, sk2, ct2);
                    assertTrue(pt_p.isEqual(pt2), "decrypt(c2) = m2");
                }
            }
        }
    }
}
