import curve.Group;
import curve.PBC;
import it.unisa.dia.gas.jpbc.Element;
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
                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC scheme = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC(curve);
                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.PublicKey pk = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.PublicKey();
                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.SecretKey sk = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.SecretKey();
                scheme.KeyGen(pk, sk);
                Element m1 = scheme.GetZrElement();
                Element m2 = scheme.GetZrElement();
                Element L1 = scheme.GetZrElement();
                Element L2 = scheme.GetZrElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");

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
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.LabelManager LM = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.LabelManager();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC scheme = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC(LM, curve, group);
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.PublicKey pk = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.PublicKey();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.SecretKey sk = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.SecretKey();
                scheme.KeyGen(LM, pk, sk);
                Element m1 = scheme.GetZrElement();
                Element m2 = scheme.GetZrElement();
                Element m3 = scheme.GetZrElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");
                assertFalse(m1.isEqual(m3), "m1 != m3");
                assertFalse(m2.isEqual(m3), "m2 != m3");
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

    @DisplayName("test paper 《Chameleon-Hashes with Ephemeral Trapdoors And Applications to Invisible Sanitizable Signatures》")
    @Nested
    class ChameleonHashesWithEphemeralTrapdoorsAndApplicationsToInvisibleSanitizableSignaturesTest {
        @DisplayName("test CH_ET_BC_CDK_2017")
        @Nested
        class CH_ET_BC_CDK_2017_Test {
            @DisplayName("test Native impl")
            @ParameterizedTest(name = "test lambda = {0}")
            @ValueSource(ints = {256, 512, 1024, 2048})
            void NativeTest(int lambda) {
                Random rand = new Random();
                scheme.CH.CH_ET_BC_CDK_2017.Native scheme = new scheme.CH.CH_ET_BC_CDK_2017.Native(lambda);
                scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey pk = new scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey();
                scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey sk = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
                scheme.KeyGen(pk, sk);
                BigInteger m1 = new BigInteger(lambda, rand);
                BigInteger m2 = new BigInteger(lambda, rand);
                scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue h1 = new scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue();
                scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue h2 = new scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue();
                scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness r1 = new scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness();
                scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness r1_p = new scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness();
                scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness r2 = new scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness();
                scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor etd1 = new scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor();
                scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor etd2 = new scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor();
                scheme.Hash(h1, r1, etd1, pk, m1);
                assertTrue(scheme.Check(h1, r1, pk, m1), "H(m1) valid");
                scheme.Hash(h2, r2, etd2, pk, m2);
                assertTrue(scheme.Check(h2, r2, pk, m2), "H(m2) valid");

                assertFalse(scheme.Check(h1, r1, pk, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pk, m1), "not H(m2)");

                scheme.Adapt(r1_p, h1, r1, etd1, pk, sk, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pk, m2), "adapt m2 valid");
                assertFalse(scheme.Check(h1, r1_p, pk, m1), "not adapt m1");
            }
        }

        @DisplayName("test CH_ET_KOG_CDK_2017")
        @Nested
        class CH_ET_KOG_CDK_2017_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} group {1}")
            @MethodSource("CHTest#GetPBCCartesianProduct")
            void JPBCTest(curve.PBC curve, Group group) {
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.PublicParam pp = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.PublicParam();
                scheme.CH.CH_ET_KOG_CDK_2017.PBC scheme = new scheme.CH.CH_ET_KOG_CDK_2017.PBC(pp, curve, group, 1024);
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.PublicKey pk = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.PublicKey();
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.SecretKey sk = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.SecretKey();
                scheme.KeyGen(pk, sk, pp);
                Element m1 = scheme.getZrElement();
                Element m2 = scheme.getZrElement();
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.HashValue h1 = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.HashValue();
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.HashValue h2 = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.HashValue();
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.Randomness r1 = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.Randomness();
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.Randomness r1_p = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.Randomness();
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.Randomness r2 = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.Randomness();
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.ETrapdoor etd1 = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.ETrapdoor();
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.ETrapdoor etd2 = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.ETrapdoor();
                scheme.Hash(h1, r1, etd1, pp, pk, m1);
                assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                scheme.Hash(h2, r2, etd2, pp, pk, m2);
                assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");

                assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                scheme.Adapt(r1_p, h1, r1, etd1, pp, pk, sk, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "adapt m2 valid");
                assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not adapt m1");
            }
        }

        @DisplayName("test CH_CDK_2017")
        @Nested
        class CH_CDK_2017_Test {
            @DisplayName("test Native impl")
            @ParameterizedTest(name = "test lambda = {0}")
            @ValueSource(ints = {256, 512, 1024, 2048})
            void NativeTest(int lambda) {
                Random rand = new Random();
                scheme.CH.CH_CDK_2017.Native scheme = new scheme.CH.CH_CDK_2017.Native(lambda);
                scheme.CH.CH_CDK_2017.Native.PublicKey pk = new scheme.CH.CH_CDK_2017.Native.PublicKey();
                scheme.CH.CH_CDK_2017.Native.SecretKey sk = new scheme.CH.CH_CDK_2017.Native.SecretKey();
                scheme.KeyGen(pk, sk);
                BigInteger m1 = new BigInteger(lambda, rand);
                BigInteger m2 = new BigInteger(lambda, rand);
                BigInteger l1 = new BigInteger(lambda, rand);
                BigInteger l2 = new BigInteger(lambda, rand);
                scheme.CH.CH_CDK_2017.Native.HashValue h1 = new scheme.CH.CH_CDK_2017.Native.HashValue();
                scheme.CH.CH_CDK_2017.Native.HashValue h2 = new scheme.CH.CH_CDK_2017.Native.HashValue();
                scheme.CH.CH_CDK_2017.Native.Randomness r1 = new scheme.CH.CH_CDK_2017.Native.Randomness();
                scheme.CH.CH_CDK_2017.Native.Randomness r1_p = new scheme.CH.CH_CDK_2017.Native.Randomness();
                scheme.CH.CH_CDK_2017.Native.Randomness r2 = new scheme.CH.CH_CDK_2017.Native.Randomness();
                scheme.Hash(h1, r1, pk, l1, m1);
                assertTrue(scheme.Check(h1, r1, pk, l1, m1), "H(l1, m1) valid");
                assertFalse(scheme.Check(h1, r1, pk, l2, m1), "not H(l2, m1)");

                scheme.Hash(h2, r2, pk, l2, m2);
                assertTrue(scheme.Check(h2, r2, pk, l2, m2), "H(l2, m2) valid");
                assertFalse(scheme.Check(h2, r2, pk, l1, m2), "not H(l1, m2)");

                assertFalse(scheme.Check(h1, r1, pk, l1, m2), "not H(l1, m2)");
                assertFalse(scheme.Check(h2, r2, pk, l2, m1), "not H(l2, m1)");

                scheme.Adapt(r1_p, r1, pk, sk, l1, m1, l2, m2);
                assertTrue(scheme.Check(h1, r1_p, pk, l2, m2), "adapt m2 valid");
                assertFalse(scheme.Check(h1, r1_p, pk, l2, m1), "not adapt m1");
                assertFalse(scheme.Check(h1, r1_p, pk, l1, m2), "not adapt l1");
            }
        }

        @DisplayName("test MCH_CDK_2017")
        @Nested
        class MCH_CDK_2017_Test {
            @DisplayName("test Native impl")
            @ParameterizedTest(name = "test lambda = {0}")
            @ValueSource(ints = {256, 512, 1024, 2048})
            void NativeTest(int lambda) {
                Random rand = new Random();
                scheme.CH.MCH_CDK_2017.Native scheme = new scheme.CH.MCH_CDK_2017.Native(lambda);
                scheme.CH.MCH_CDK_2017.Native.PublicKey pk = new scheme.CH.MCH_CDK_2017.Native.PublicKey();
                scheme.CH.MCH_CDK_2017.Native.SecretKey sk = new scheme.CH.MCH_CDK_2017.Native.SecretKey();
                scheme.KeyGen(pk, sk);
                BigInteger m1 = new BigInteger(lambda, rand);
                BigInteger m2 = new BigInteger(lambda, rand);
                scheme.CH.MCH_CDK_2017.Native.HashValue h1 = new scheme.CH.MCH_CDK_2017.Native.HashValue();
                scheme.CH.MCH_CDK_2017.Native.HashValue h2 = new scheme.CH.MCH_CDK_2017.Native.HashValue();
                scheme.CH.MCH_CDK_2017.Native.Randomness r1 = new scheme.CH.MCH_CDK_2017.Native.Randomness();
                scheme.CH.MCH_CDK_2017.Native.Randomness r1_p = new scheme.CH.MCH_CDK_2017.Native.Randomness();
                scheme.CH.MCH_CDK_2017.Native.Randomness r2 = new scheme.CH.MCH_CDK_2017.Native.Randomness();
                scheme.Hash(h1, r1, pk, m1);
                assertTrue(scheme.Check(h1, r1, pk, m1), "H(m1) valid");
                scheme.Hash(h2, r2, pk, m2);
                assertTrue(scheme.Check(h2, r2, pk, m2), "H(m2) valid");

                assertFalse(scheme.Check(h1, r1, pk, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pk, m1), "not H(m2)");

                scheme.Adapt(r1_p, r1, pk, sk, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pk, m2), "adapt m2 valid");
                assertFalse(scheme.Check(h1, r1_p, pk, m1), "not adapt m1");
            }
        }

        @DisplayName("test CHET_RSA_CDK_2017")
        @Nested
        class CHET_RSA_CDK_2017_Test {
            @DisplayName("test Native impl")
            @ParameterizedTest(name = "test lambda = {0}")
            @ValueSource(ints = {128, 256, 512})
            void NativeTest(int lambda) {
                Random rand = new Random();
                scheme.CH.CHET_RSA_CDK_2017.Native scheme = new scheme.CH.CHET_RSA_CDK_2017.Native(lambda);
                scheme.CH.CHET_RSA_CDK_2017.Native.PublicKey pk = new scheme.CH.CHET_RSA_CDK_2017.Native.PublicKey();
                scheme.CH.CHET_RSA_CDK_2017.Native.SecretKey sk = new scheme.CH.CHET_RSA_CDK_2017.Native.SecretKey();
                scheme.KeyGen(pk, sk);
                BigInteger m1 = new BigInteger(lambda, rand);
                BigInteger m2 = new BigInteger(lambda, rand);
                assertTrue(m1.compareTo(m2) != 0, "m1 != m2");
                scheme.CH.CHET_RSA_CDK_2017.Native.HashValue h1 = new scheme.CH.CHET_RSA_CDK_2017.Native.HashValue();
                scheme.CH.CHET_RSA_CDK_2017.Native.HashValue h2 = new scheme.CH.CHET_RSA_CDK_2017.Native.HashValue();
                scheme.CH.CHET_RSA_CDK_2017.Native.Randomness r1 = new scheme.CH.CHET_RSA_CDK_2017.Native.Randomness();
                scheme.CH.CHET_RSA_CDK_2017.Native.Randomness r1_p = new scheme.CH.CHET_RSA_CDK_2017.Native.Randomness();
                scheme.CH.CHET_RSA_CDK_2017.Native.Randomness r2 = new scheme.CH.CHET_RSA_CDK_2017.Native.Randomness();
                scheme.CH.CHET_RSA_CDK_2017.Native.ETrapdoor etd1 = new scheme.CH.CHET_RSA_CDK_2017.Native.ETrapdoor();
                scheme.CH.CHET_RSA_CDK_2017.Native.ETrapdoor etd2 = new scheme.CH.CHET_RSA_CDK_2017.Native.ETrapdoor();
                scheme.Hash(h1, r1, etd1, pk, m1);
                assertTrue(scheme.Check(h1, r1, pk, m1), "H(m1) valid");
                scheme.Hash(h2, r2, etd2, pk, m2);
                assertTrue(scheme.Check(h2, r2, pk, m2), "H(m2) valid");

                assertFalse(scheme.Check(h1, r1, pk, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pk, m1), "not H(m2)");

                scheme.Adapt(r1_p, h1, r1, etd1, pk, sk, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pk, m2), "adapt m2 valid");
                assertFalse(scheme.Check(h1, r1_p, pk, m1), "not adapt m1");
            }
        }
    }

    @DisplayName("test paper 《Chameleon Hashing without Key Exposure》")
    @Nested
    class ChameleonHashingWithoutKeyExposureTest {
        @DisplayName("test CH_KEF_CZK_2004")
        @Nested
        class CH_KEF_CZK_2004_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} group {1}")
            @MethodSource("CHTest#GetPBCCartesianProduct")
            void JPBCTest(curve.PBC curve, Group group) {
                scheme.CH.CH_KEF_CZK_2004.PBC scheme = new scheme.CH.CH_KEF_CZK_2004.PBC();
                scheme.CH.CH_KEF_CZK_2004.PBC.PublicParam SP = new scheme.CH.CH_KEF_CZK_2004.PBC.PublicParam();
                scheme.SetUp(SP, curve, group);
                scheme.CH.CH_KEF_CZK_2004.PBC.PublicKey pk = new scheme.CH.CH_KEF_CZK_2004.PBC.PublicKey();
                scheme.CH.CH_KEF_CZK_2004.PBC.SecretKey sk = new scheme.CH.CH_KEF_CZK_2004.PBC.SecretKey();
                scheme.KeyGen(pk, sk, SP);
                Element m1 = scheme.GetZrElement();
                Element m2 = scheme.GetZrElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");
                Element L1;
                Element L2;
                // these group has wrong behave in fromhash
                if(group == Group.GT && (curve == PBC.D_159 || curve == PBC.D_201 || curve == PBC.D_224 || curve == PBC.D_105171_196_185
                        || curve == PBC.D_277699_175_167 || curve == PBC.D_278027_190_181 || curve == PBC.F || curve == PBC.SM_9 || curve == PBC.G_149)) {
                    L1 = SP.GetGElement();
                    L2 = SP.GetGElement();
                } else {
                    L1 = SP.H("S11|R11|T11");
                    L2 = SP.H("S22|R22|T22");
                }
                assertFalse(L1.isEqual(L2), "L1 != L2");
                scheme.CH.CH_KEF_CZK_2004.PBC.HashValue h1 = new scheme.CH.CH_KEF_CZK_2004.PBC.HashValue();
                scheme.CH.CH_KEF_CZK_2004.PBC.HashValue h2 = new scheme.CH.CH_KEF_CZK_2004.PBC.HashValue();
                scheme.CH.CH_KEF_CZK_2004.PBC.Randomness r1 = new scheme.CH.CH_KEF_CZK_2004.PBC.Randomness();
                scheme.CH.CH_KEF_CZK_2004.PBC.Randomness r2 = new scheme.CH.CH_KEF_CZK_2004.PBC.Randomness();
                scheme.CH.CH_KEF_CZK_2004.PBC.Randomness r1_p = new scheme.CH.CH_KEF_CZK_2004.PBC.Randomness();
                scheme.Hash(h1, r1, SP, pk, L1, m1);
                assertTrue(scheme.Check(h1, r1, SP, L1, m1), "H(L1, m1) valid");
                assertFalse(scheme.Check(h1, r1, SP, L2, m1), "not H(L2, m1)");

                scheme.Hash(h2, r2, SP, pk, L2, m2);
                assertTrue(scheme.Check(h2, r2, SP, L2, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, SP, L1, m2), "not H(L1, m2)");

                assertFalse(scheme.Check(h1, r1, SP, L2, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, SP, L1, m1), "not H(m2)");

                scheme.Adapt(r1_p, r1, SP, sk, L1, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, SP, L1, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h2, r1_p, SP, L1, m1), "not Adapt(m1)");
            }
        }
    }

    @DisplayName("test paper 《Discrete logarithm based chameleon hashing and signatures withoutkey exposure》")
    @Nested
    class DiscreteLogarithmBasedChameleonHashingAndSignaturesWithoutkeyExposureTest {
        @DisplayName("test CH_KEF_DL_CZT_2011")
        @Nested
        class CH_KEF_DL_CZT_2011_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} group {1}")
            @MethodSource("CHTest#GetPBCCartesianProduct")
            void JPBCTest(curve.PBC curve, Group group) {
                // these group has wrong behave in fromhash
                if(group == Group.GT && (curve == PBC.D_159 || curve == PBC.D_201 || curve == PBC.D_224 || curve == PBC.D_105171_196_185
                        || curve == PBC.D_277699_175_167 || curve == PBC.D_278027_190_181 || curve == PBC.F || curve == PBC.SM_9 || curve == PBC.G_149)) {
                    return;
                }
                scheme.CH.CH_KEF_DL_CZT_2011.PBC scheme = new scheme.CH.CH_KEF_DL_CZT_2011.PBC();
                scheme.CH.CH_KEF_DL_CZT_2011.PBC.PublicParam SP = new scheme.CH.CH_KEF_DL_CZT_2011.PBC.PublicParam();
                scheme.SetUp(SP, curve, group);
                scheme.CH.CH_KEF_DL_CZT_2011.PBC.PublicKey pk = new scheme.CH.CH_KEF_DL_CZT_2011.PBC.PublicKey();
                scheme.CH.CH_KEF_DL_CZT_2011.PBC.SecretKey sk = new scheme.CH.CH_KEF_DL_CZT_2011.PBC.SecretKey();
                scheme.KeyGen(pk, sk, SP);
                Element m1 = scheme.GetZrElement();
                Element m2 = scheme.GetZrElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");
                Element L1 = SP.GetGElement();
                Element L2 = SP.GetGElement();
                assertFalse(L1.isEqual(L2), "L1 != L2");
                scheme.CH.CH_KEF_DL_CZT_2011.PBC.HashValue h1 = new scheme.CH.CH_KEF_DL_CZT_2011.PBC.HashValue();
                scheme.CH.CH_KEF_DL_CZT_2011.PBC.HashValue h2 = new scheme.CH.CH_KEF_DL_CZT_2011.PBC.HashValue();
                scheme.CH.CH_KEF_DL_CZT_2011.PBC.Randomness r1 = new scheme.CH.CH_KEF_DL_CZT_2011.PBC.Randomness();
                scheme.CH.CH_KEF_DL_CZT_2011.PBC.Randomness r2 = new scheme.CH.CH_KEF_DL_CZT_2011.PBC.Randomness();
                scheme.CH.CH_KEF_DL_CZT_2011.PBC.Randomness r1_p = new scheme.CH.CH_KEF_DL_CZT_2011.PBC.Randomness();
                scheme.Hash(h1, r1, SP, pk, L1, m1);
                assertTrue(scheme.Check(h1, r1, SP, pk, L1, m1), "H(L1, m1) valid");
                assertFalse(scheme.Check(h1, r1, SP, pk, L2, m1), "not H(L2, m1)");

                scheme.Hash(h2, r2, SP, pk, L2, m2);
                assertTrue(scheme.Check(h2, r2, SP, pk, L2, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, SP, pk, L1, m2), "not H(L1, m2)");

                assertFalse(scheme.Check(h1, r1, SP, pk, L2, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, SP, pk, L1, m1), "not H(m2)");

                scheme.Adapt(r1_p, r1, SP, pk, sk, L1, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, SP, pk, L1, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h2, r1_p, SP, pk, L1, m1), "not Adapt(m1)");
            }
        }
    }
}
