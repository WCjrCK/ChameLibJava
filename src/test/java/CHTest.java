import curve.Group;
import curve.PBC;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;

import java.math.BigInteger;
import java.util.EnumSet;
import java.util.Random;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

public class CHTest {
    public static Stream<Arguments> GetPBCCartesianProduct() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a -> EnumSet.allOf(Group.class).stream().flatMap(b -> Stream.of(Arguments.of(a, b))));
    }

    @BeforeAll
    static void initTest() {
        InitialLib();
    }

    @DisplayName("test paper 《On the Key Exposure Problem in Chameleon Hashes》")
    @Nested
    class OnTheKeyExposureProblemInChameleonHashesTest {
        @DisplayName("test CH_KEF_NoMH_AM_2004")
        @Nested
        class CH_KEF_NoMH_AM_2004_Test {
            @DisplayName("test native impl")
            @Test
            void NativeTest() {
                Random rand = new Random();
                scheme.CH.CH_KEF_NoMH_AM_2004.Native scheme = new scheme.CH.CH_KEF_NoMH_AM_2004.Native();
                scheme.CH.CH_KEF_NoMH_AM_2004.Native.PublicKey pk = new scheme.CH.CH_KEF_NoMH_AM_2004.Native.PublicKey();
                scheme.CH.CH_KEF_NoMH_AM_2004.Native.SecretKey sk = new scheme.CH.CH_KEF_NoMH_AM_2004.Native.SecretKey();
                scheme.KeyGen(pk, sk, 512);
                BigInteger m1 = new BigInteger(256, rand);
                BigInteger m2 = new BigInteger(256, rand);
                assertTrue(m1.compareTo(m2) != 0, "m1 != m2");
                scheme.CH.CH_KEF_NoMH_AM_2004.Native.HashValue h1 = new scheme.CH.CH_KEF_NoMH_AM_2004.Native.HashValue();
                scheme.CH.CH_KEF_NoMH_AM_2004.Native.HashValue h2 = new scheme.CH.CH_KEF_NoMH_AM_2004.Native.HashValue();
                scheme.CH.CH_KEF_NoMH_AM_2004.Native.Randomness r1 = new scheme.CH.CH_KEF_NoMH_AM_2004.Native.Randomness();
                scheme.CH.CH_KEF_NoMH_AM_2004.Native.Randomness r2 = new scheme.CH.CH_KEF_NoMH_AM_2004.Native.Randomness();
                scheme.CH.CH_KEF_NoMH_AM_2004.Native.Randomness r1_p = new scheme.CH.CH_KEF_NoMH_AM_2004.Native.Randomness();
                scheme.Hash(h1, r1, pk, m1);
                assertTrue(scheme.Check(h1, r1, pk, m1), "H(m1) valid");
                scheme.Hash(h2, r2, pk, m2);
                assertTrue(scheme.Check(h2, r2, pk, m2), "H(m2) valid");

                assertFalse(scheme.Check(h1, r1, pk, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pk, m1), "not H(m2)");

                scheme.Adapt(r1_p, h1, pk, sk, m2);
                assertTrue(scheme.Check(h1, r1_p, pk, m2), "Adapt(m2) valid");
            }
        }

        @DisplayName("test CH_KEF_MH_RSA_F_AM_2004")
        @Nested
        class CH_KEF_MH_RSA_F_AM_2004_Test {
            @DisplayName("test native impl")
            @Test
            void NativeTest() {
                Random rand = new Random();
                scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native scheme = new scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native();
                scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.PublicParam pp = new scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.PublicParam();
                scheme.SetUp(pp, 512, 1024);
                scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.PublicKey pk = new scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.PublicKey();
                scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.SecretKey sk = new scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.SecretKey();
                scheme.KeyGen(pk, sk, pp);
                BigInteger m1 = new BigInteger(256, rand);
                BigInteger m2 = new BigInteger(256, rand);
                BigInteger L1 = new BigInteger(512, rand);
                BigInteger L2 = new BigInteger(512, rand);
                assertTrue(m1.compareTo(m2) != 0, "m1 != m2");
                scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.HashValue h1 = new scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.HashValue();
                scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.HashValue h2 = new scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.HashValue();
                scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.Randomness r1 = new scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.Randomness();
                scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.Randomness r2 = new scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.Randomness();
                scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.Randomness r1_p = new scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.Randomness();
                scheme.Hash(h1, r1, pk, L1, m1, pp);
                assertTrue(scheme.Check(h1, r1, pk, L1, m1, pp), "H(L1, m1) valid");
                assertFalse(scheme.Check(h1, r1, pk, L2, m1, pp), "not H(L2, m1)");
                scheme.Hash(h2, r2, pk, L2, m2, pp);
                assertTrue(scheme.Check(h2, r2, pk, L2, m2, pp), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, pk, L1, m2, pp), "not H(L1, m2)");

                assertFalse(scheme.Check(h1, r1, pk, L2, m2, pp), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pk, L1, m1, pp), "not H(m2)");

                scheme.Adapt(r1_p, r1, pk, sk, L1, m1, m2, pp);
                assertTrue(scheme.Check(h1, r1_p, pk, L1, m2, pp), "Adapt(m2) valid");

                scheme.Adapt(r1_p, r1, pk, sk, L2, m1, m2, pp);
                assertFalse(scheme.Check(h1, r1_p, pk, L2, m2, pp), "not Adapt(m2)");
            }
        }

        @DisplayName("test CH_KEF_MH_RSANN_F_AM_2004")
        @Nested
        class CH_KEF_MH_RSANN_F_AM_2004_Test {
            @DisplayName("test native impl")
            @Test
            void NativeTest() {
                Random rand = new Random();
                scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native scheme = new scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native();
                scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.PublicKey pk = new scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.PublicKey();
                scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.SecretKey sk = new scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.SecretKey();
                scheme.KeyGen(pk, sk, 512);
                BigInteger m1 = new BigInteger(256, rand);
                BigInteger m2 = new BigInteger(256, rand);
                BigInteger L1 = new BigInteger(512, rand);
                BigInteger L2 = new BigInteger(512, rand);
                assertTrue(m1.compareTo(m2) != 0, "m1 != m2");
                scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.HashValue h1 = new scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.HashValue();
                scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.HashValue h2 = new scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.HashValue();
                scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.Randomness r1 = new scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.Randomness();
                scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.Randomness r2 = new scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.Randomness();
                scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.Randomness r1_p = new scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.Randomness();
                scheme.Hash(h1, r1, pk, L1, m1);
                assertTrue(scheme.Check(h1, r1, pk, L1, m1), "H(L1, m1) valid");
                assertFalse(scheme.Check(h1, r1, pk, L2, m1), "not H(L2, m1)");
                scheme.Hash(h2, r2, pk, L2, m2);
                assertTrue(scheme.Check(h2, r2, pk, L2, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, pk, L1, m2), "not H(L1, m2)");

                assertFalse(scheme.Check(h1, r1, pk, L2, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pk, L1, m1), "not H(m2)");

                scheme.Adapt(r1_p, h1, pk, sk, L1, m2);
                assertTrue(scheme.Check(h1, r1_p, pk, L1, m2), "Adapt(m2) valid");

    //            scheme.Adapt(r1_p, h1, pk, sk, L2, m2);
    //            assertFalse(scheme.Check(h1, r1_p, pk, L2, m2), "not Adapt(m2)");
            }
        }

        @DisplayName("test CH_KEF_MH_SDH_DL_AM_2004")
        @Nested
        class CH_KEF_MH_SDH_DL_AM_2004_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0}")
            @EnumSource(names = {"A", "A1", "E"})
            void JPBCTest(PBC curve) {
                Random rand = new Random();
                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC scheme = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC(curve);
                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.PublicKey pk = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.PublicKey();
                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.SecretKey sk = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.SecretKey();
                scheme.KeyGen(pk, sk);
                BigInteger m1 = new BigInteger(256, rand);
                BigInteger m2 = new BigInteger(256, rand);
                BigInteger L1 = new BigInteger(512, rand);
                BigInteger L2 = new BigInteger(512, rand);
                assertTrue(m1.compareTo(m2) != 0, "m1 != m2");

                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.HashValue h1 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.HashValue();
                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.HashValue h2 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.HashValue();
                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.Randomness r1 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.Randomness();
                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.Randomness r2 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.Randomness();
                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.Randomness r1_p = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.Randomness();
                scheme.Hash(h1, r1, pk, L1, m1);
                assertTrue(scheme.Check(h1, r1, pk, L1, m1), "H(L1, m1) valid");
                assertFalse(scheme.Check(h1, r1, pk, L2, m1), "not H(L2, m1)");
                scheme.Hash(h2, r2, pk, L2, m2);
                assertTrue(scheme.Check(h2, r2, pk, L2, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, pk, L1, m2), "not H(L1, m2)");

                assertFalse(scheme.Check(h1, r1, pk, L2, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pk, L1, m1), "not H(m2)");

                scheme.Adapt(r1_p, r1, pk, sk, L1, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pk, L1, m2), "Adapt(m2) valid");

                scheme.Adapt(r1_p, r1, pk, sk, L2, m1, m2);
                assertFalse(scheme.Check(h1, r1_p, pk, L2, m2), "not Adapt(m2)");
            }
        }

    }

    @DisplayName("test paper 《Key exposure free chameleon hash schemes based on discrete logarithm problem》")
    @Nested
    class KeyExposureFreeChameleonHashSchemesBasedOnDiscreteLogarithmProblemTest {
        @DisplayName("test CH_KEF_DLP_LLA_2012")
        @Nested
        class CH_KEF_DLP_LLA_2012_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} group {1}")
            @MethodSource("CHTest#GetPBCCartesianProduct")
            void JPBCTest(curve.PBC curve, Group group) {
                Random rand = new Random();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.LabelManager LM = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.LabelManager();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC scheme = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC(LM, curve, group);
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.PublicKey pk = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.PublicKey();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.SecretKey sk = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.SecretKey();
                scheme.KeyGen(LM, pk, sk);
                BigInteger m1 = new BigInteger(256, rand);
                BigInteger m2 = new BigInteger(256, rand);
                BigInteger m3 = new BigInteger(256, rand);
                assertTrue(m1.compareTo(m2) != 0, "m1 != m2");
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Label L1 = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Label();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Label L2 = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Label();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.HashValue h1 = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.HashValue();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.HashValue h2 = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.HashValue();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Randomness r1 = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Randomness();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Randomness r2 = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Randomness();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Randomness r1_p = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Randomness();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Randomness r1_pp = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Randomness();
                scheme.Hash(h1, r1, L1, LM, pk, m1);
                scheme.Hash(h2, r2, L2, LM, pk, m2);
                assertTrue(scheme.Check(h1, r1, pk, L1, m1), "H(L1, m1) valid");
                assertFalse(scheme.Check(h1, r1, pk, L2, m1), "not H(L2, m1)");

                assertTrue(scheme.Check(h2, r2, pk, L2, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, pk, L1, m2), "not H(L1, m2)");

                assertFalse(scheme.Check(h1, r1, pk, L2, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pk, L1, m1), "not H(m2)");

                scheme.UForge(r1_p, h1, r1, L1, pk, sk, m1, m3);
                assertTrue(scheme.Check(h1, r1_p, pk, L1, m3), "Adapt(m3) valid");

                scheme.UForge(r1_p, h1, r1, L1, pk, sk, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pk, L1, m2), "Adapt(m2) valid");

                scheme.IForge(r1_pp, r1, r1_p, m1, m2, m3);
                assertTrue(scheme.Check(h1, r1_pp, pk, L1, m3), "Adapt(m3) valid");
            }
        }
    }
}
