import ChameleonHash.CH.DEPRECATED.MCH_CDK_2017.Native;
import com.herumi.mcl.*;
import curve.Group;
import curve.MCL;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import utils.Func;

import java.math.BigInteger;
import java.util.EnumSet;
import java.util.Random;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

@SuppressWarnings("rawtypes")
public class CHTest {
    public static Stream<Arguments> GetPBCCartesianProduct() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a -> EnumSet.allOf(Group.class).stream().flatMap(b -> Stream.of(Arguments.of(a, b))));
    }

    @BeforeEach
    void initTest() {
        InitialLib();
    }

    @DisplayName("test NIZK")
    @Nested
    class NIZKTest {
        @DisplayName("test PBC impl")
        @ParameterizedTest(name = "test curve {0} group {1}")
        @MethodSource("CHTest#GetPBCCartesianProduct")
        void JPBCTest(curve.PBC curve, Group group) {
            Pairing pairing = Func.PairingGen(curve);
            Field G = Func.GetPBCField(pairing, group);
            Field Zr = pairing.getZr();

            Element x1 = Zr.newRandomElement().getImmutable();
            Element g1 = G.newRandomElement().getImmutable();
            Element y1 = g1.powZn(x1).getImmutable();
            Element yt = G.newRandomElement().getImmutable();

            base.NIZK.PBC.DL_Proof pi1 = new base.NIZK.PBC.DL_Proof(Zr, x1, g1, y1);

            assertTrue(pi1.Check(g1, y1), "proof pass");
            assertFalse(pi1.Check(g1, yt), "proof fail");

            Element g2 = G.newRandomElement().getImmutable();
            Element y2 = g2.powZn(x1).getImmutable();

            base.NIZK.PBC.EQUAL_DL_Proof pi2 = new base.NIZK.PBC.EQUAL_DL_Proof(Zr, x1, g1, y1, g2, y2);

            assertTrue(pi2.Check(g1, y1, g2, y2), "proof pass");
            assertFalse(pi2.Check(g1, yt, g2, y2), "proof fail");
            assertFalse(pi2.Check(g1, y1, g2, yt), "proof fail");
            assertFalse(pi2.Check(g1, y2, g2, y1), "proof fail");

            base.NIZK.PBC.DH_PAIR_Proof pi4 = new base.NIZK.PBC.DH_PAIR_Proof(Zr, x1, g1, y1, g2, y2, Func.GetNdonr(group, Func.PairingParam(curve)));

            assertTrue(pi4.Check(g1, y1, g2, y2), "proof pass");
            assertFalse(pi4.Check(g1, yt, g2, y2), "proof fail");
            assertFalse(pi4.Check(g1, y1, g2, yt), "proof fail");
            assertFalse(pi4.Check(g1, y2, g2, y1), "proof fail");

            Element x2 = Zr.newRandomElement().getImmutable();
            y2 = g2.powZn(x2).getImmutable();
            Element y3 = y1.mul(y2).getImmutable();

            base.NIZK.PBC.REPRESENT_Proof pi3 = new base.NIZK.PBC.REPRESENT_Proof(Zr, y3, g1, x1, g2, x2);

            assertTrue(pi3.Check(y3, g1, g2), "proof pass");
            assertFalse(pi3.Check(y3, g1, yt), "proof fail");
            assertFalse(pi3.Check(y3, g2, g1), "proof fail");
        }

        @DisplayName("test MCL impl")
        @ParameterizedTest(name = "test curve {0}")
        // UnitTest.CurveLib.BadCaseTest#MCL_Bad_Case#Case2
        @EnumSource(names = {"BN254", "BLS12_381"})
        @SuppressWarnings("SuspiciousNameCombination")
        void MCLTest(MCL curve) {
            Func.MCLInit(curve);
            G1[] G1_tmp = new G1[]{new G1(), new G1(), new G1()};
            G2[] G2_tmp = new G2[]{new G2(), new G2(), new G2()};
            GT[] GT_tmp = new GT[]{new GT(), new GT(), new GT()};
            Fr[] Fr_tmp = new Fr[]{new Fr(), new Fr(), new Fr()};
            {
                Fr x1 = new Fr();
                Func.GetMCLZrRandomElement(x1);
                G1 g1 = new G1();
                Func.GetMCLG1RandomElement(g1);
                G1 y1 = new G1();
                Mcl.mul(y1, g1, x1);
                G1 yt = new G1();
                Func.GetMCLG1RandomElement(yt);

                base.NIZK.MCL_G1.DL_Proof pi1 = new base.NIZK.MCL_G1.DL_Proof(x1, g1, y1, Fr_tmp);

                assertTrue(pi1.Check(g1, y1, G1_tmp, Fr_tmp), "proof pass");
                assertFalse(pi1.Check(g1, yt, G1_tmp, Fr_tmp), "proof fail");

                G1 g2 = new G1();
                Func.GetMCLG1RandomElement(g2);
                G1 y2 = new G1();
                Mcl.mul(y2, g2, x1);

                base.NIZK.MCL_G1.EQUAL_DL_Proof pi2 = new base.NIZK.MCL_G1.EQUAL_DL_Proof(x1, g1, y1, g2, y2, Fr_tmp);

                assertTrue(pi2.Check(g1, y1, g2, y2, G1_tmp, Fr_tmp), "proof pass");
                assertFalse(pi2.Check(g1, yt, g2, y2, G1_tmp, Fr_tmp), "proof fail");
                assertFalse(pi2.Check(g1, y1, g2, yt, G1_tmp, Fr_tmp), "proof fail");
                assertFalse(pi2.Check(g1, y2, g2, y1, G1_tmp, Fr_tmp), "proof fail");

                base.NIZK.MCL_G1.DH_PAIR_Proof pi4 = new base.NIZK.MCL_G1.DH_PAIR_Proof(x1, g1, y1, g2, y2, G1_tmp, Fr_tmp);

                assertTrue(pi4.Check(g1, y1, g2, y2, G1_tmp, Fr_tmp), "proof pass");
                assertFalse(pi4.Check(g1, yt, g2, y2, G1_tmp, Fr_tmp), "proof fail");
                assertFalse(pi4.Check(g1, y1, g2, yt, G1_tmp, Fr_tmp), "proof fail");
                assertFalse(pi4.Check(g1, y2, g2, y1, G1_tmp, Fr_tmp), "proof fail");

                Fr x2 = new Fr();
                Func.GetMCLZrRandomElement(x2);
                Mcl.mul(y2, g2, x2);
                G1 y3 = new G1();
                Mcl.add(y3, y1, y2);

                base.NIZK.MCL_G1.REPRESENT_Proof pi3 = new base.NIZK.MCL_G1.REPRESENT_Proof(y3, g1, x1, g2, x2, G1_tmp, Fr_tmp);

                assertTrue(pi3.Check(y3, g1, g2, G1_tmp, Fr_tmp), "proof pass");
                assertFalse(pi3.Check(y3, g1, yt, G1_tmp, Fr_tmp), "proof fail");
                assertFalse(pi3.Check(y3, g2, g1, G1_tmp, Fr_tmp), "proof fail");
            }
            if(curve != MCL.SECP256K1) {
                // UnitTest.CurveLib.BadCaseTest#MCL_Bad_Case#Case1
                Fr x1 = new Fr();
                Func.GetMCLZrRandomElement(x1);
                G2 g1 = new G2();
                Func.GetMCLG2RandomElement(g1);
                G2 y1 = new G2();
                Mcl.mul(y1, g1, x1);
                G2 yt = new G2();
                Func.GetMCLG2RandomElement(yt);

                base.NIZK.MCL_G2.DL_Proof pi1 = new base.NIZK.MCL_G2.DL_Proof(x1, g1, y1, Fr_tmp);

                assertTrue(pi1.Check(g1, y1, G2_tmp, Fr_tmp), "proof pass");
                assertFalse(pi1.Check(g1, yt, G2_tmp, Fr_tmp), "proof fail");

                G2 g2 = new G2();
                Func.GetMCLG2RandomElement(g2);
                G2 y2 = new G2();
                Mcl.mul(y2, g2, x1);

                base.NIZK.MCL_G2.EQUAL_DL_Proof pi2 = new base.NIZK.MCL_G2.EQUAL_DL_Proof(x1, g1, y1, g2, y2, Fr_tmp);

                assertTrue(pi2.Check(g1, y1, g2, y2, G2_tmp, Fr_tmp), "proof pass");
                assertFalse(pi2.Check(g1, yt, g2, y2, G2_tmp, Fr_tmp), "proof fail");
                assertFalse(pi2.Check(g1, y1, g2, yt, G2_tmp, Fr_tmp), "proof fail");
                assertFalse(pi2.Check(g1, y2, g2, y1, G2_tmp, Fr_tmp), "proof fail");

                base.NIZK.MCL_G2.DH_PAIR_Proof pi4 = new base.NIZK.MCL_G2.DH_PAIR_Proof(x1, g1, y1, g2, y2, G2_tmp, Fr_tmp);

                assertTrue(pi4.Check(g1, y1, g2, y2, G2_tmp, Fr_tmp), "proof pass");
                assertFalse(pi4.Check(g1, yt, g2, y2, G2_tmp, Fr_tmp), "proof fail");
                assertFalse(pi4.Check(g1, y1, g2, yt, G2_tmp, Fr_tmp), "proof fail");
                assertFalse(pi4.Check(g1, y2, g2, y1, G2_tmp, Fr_tmp), "proof fail");

                Fr x2 = new Fr();
                Func.GetMCLZrRandomElement(x2);
                Mcl.mul(y2, g2, x2);
                G2 y3 = new G2();
                Mcl.add(y3, y1, y2);

                base.NIZK.MCL_G2.REPRESENT_Proof pi3 = new base.NIZK.MCL_G2.REPRESENT_Proof(y3, g1, x1, g2, x2, G2_tmp, Fr_tmp);

                assertTrue(pi3.Check(y3, g1, g2, G2_tmp, Fr_tmp), "proof pass");
                assertFalse(pi3.Check(y3, g1, yt, G2_tmp, Fr_tmp), "proof fail");
                assertFalse(pi3.Check(y3, g2, g1, G2_tmp, Fr_tmp), "proof fail");
            }

            {
                // UnitTest.CurveLib.BadCaseTest#MCL_Bad_Case#Case1
                Fr x1 = new Fr();
                Func.GetMCLZrRandomElement(x1);
                GT g1 = new GT();
                Func.GetMCLGTRandomElement(g1);
                GT y1 = new GT();
                Mcl.pow(y1, g1, x1);
                GT yt = new GT();
                Func.GetMCLGTRandomElement(yt);

                base.NIZK.MCL_GT.DL_Proof pi1 = new base.NIZK.MCL_GT.DL_Proof(x1, g1, y1, Fr_tmp);

                assertTrue(pi1.Check(g1, y1, GT_tmp, Fr_tmp), "proof pass");
                assertFalse(pi1.Check(g1, yt, GT_tmp, Fr_tmp), "proof fail");

                GT g2 = new GT();
                Func.GetMCLGTRandomElement(g2);
                GT y2 = new GT();
                Mcl.pow(y2, g2, x1);

                base.NIZK.MCL_GT.EQUAL_DL_Proof pi2 = new base.NIZK.MCL_GT.EQUAL_DL_Proof(x1, g1, y1, g2, y2, Fr_tmp);

                assertTrue(pi2.Check(g1, y1, g2, y2, GT_tmp, Fr_tmp), "proof pass");
                assertFalse(pi2.Check(g1, yt, g2, y2, GT_tmp, Fr_tmp), "proof fail");
                assertFalse(pi2.Check(g1, y1, g2, yt, GT_tmp, Fr_tmp), "proof fail");
                assertFalse(pi2.Check(g1, y2, g2, y1, GT_tmp, Fr_tmp), "proof fail");

                base.NIZK.MCL_GT.DH_PAIR_Proof pi4 = new base.NIZK.MCL_GT.DH_PAIR_Proof(x1, g1, y1, g2, y2, GT_tmp, Fr_tmp);

                assertTrue(pi4.Check(g1, y1, g2, y2, GT_tmp, Fr_tmp), "proof pass");
                assertFalse(pi4.Check(g1, yt, g2, y2, GT_tmp, Fr_tmp), "proof fail");
                assertFalse(pi4.Check(g1, y1, g2, yt, GT_tmp, Fr_tmp), "proof fail");
                assertFalse(pi4.Check(g1, y2, g2, y1, GT_tmp, Fr_tmp), "proof fail");

                Fr x2 = new Fr();
                Func.GetMCLZrRandomElement(x2);
                Mcl.pow(y2, g2, x2);
                GT y3 = new GT();
                Mcl.mul(y3, y1, y2);

                base.NIZK.MCL_GT.REPRESENT_Proof pi3 = new base.NIZK.MCL_GT.REPRESENT_Proof(y3, g1, x1, g2, x2, GT_tmp, Fr_tmp);

                assertTrue(pi3.Check(y3, g1, g2, GT_tmp, Fr_tmp), "proof pass");
                assertFalse(pi3.Check(y3, g1, yt, GT_tmp, Fr_tmp), "proof fail");
                assertFalse(pi3.Check(y3, g2, g1, GT_tmp, Fr_tmp), "proof fail");
            }
        }
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
                ChameleonHash.CH.DEPRECATED.CH_KEF_NoMH_AM_2004.Native scheme = new ChameleonHash.CH.DEPRECATED.CH_KEF_NoMH_AM_2004.Native();
                ChameleonHash.CH.DEPRECATED.CH_KEF_NoMH_AM_2004.Native.PublicKey pk = new ChameleonHash.CH.DEPRECATED.CH_KEF_NoMH_AM_2004.Native.PublicKey();
                ChameleonHash.CH.DEPRECATED.CH_KEF_NoMH_AM_2004.Native.SecretKey sk = new ChameleonHash.CH.DEPRECATED.CH_KEF_NoMH_AM_2004.Native.SecretKey();
                scheme.KeyGen(pk, sk, 512);
                BigInteger m1 = new BigInteger(256, rand);
                BigInteger m2 = new BigInteger(256, rand);
                assertTrue(m1.compareTo(m2) != 0, "m1 != m2");
                ChameleonHash.CH.DEPRECATED.CH_KEF_NoMH_AM_2004.Native.HashValue h1 = new ChameleonHash.CH.DEPRECATED.CH_KEF_NoMH_AM_2004.Native.HashValue();
                ChameleonHash.CH.DEPRECATED.CH_KEF_NoMH_AM_2004.Native.HashValue h2 = new ChameleonHash.CH.DEPRECATED.CH_KEF_NoMH_AM_2004.Native.HashValue();
                ChameleonHash.CH.DEPRECATED.CH_KEF_NoMH_AM_2004.Native.Randomness r1 = new ChameleonHash.CH.DEPRECATED.CH_KEF_NoMH_AM_2004.Native.Randomness();
                ChameleonHash.CH.DEPRECATED.CH_KEF_NoMH_AM_2004.Native.Randomness r2 = new ChameleonHash.CH.DEPRECATED.CH_KEF_NoMH_AM_2004.Native.Randomness();
                ChameleonHash.CH.DEPRECATED.CH_KEF_NoMH_AM_2004.Native.Randomness r1_p = new ChameleonHash.CH.DEPRECATED.CH_KEF_NoMH_AM_2004.Native.Randomness();
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
                ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSA_F_AM_2004.Native scheme = new ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSA_F_AM_2004.Native();
                ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSA_F_AM_2004.Native.PublicParam pp = new ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSA_F_AM_2004.Native.PublicParam();
                scheme.SetUp(pp, 512, 1024);
                ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSA_F_AM_2004.Native.PublicKey pk = new ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSA_F_AM_2004.Native.PublicKey();
                ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSA_F_AM_2004.Native.SecretKey sk = new ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSA_F_AM_2004.Native.SecretKey();
                scheme.KeyGen(pk, sk, pp);
                BigInteger m1 = new BigInteger(256, rand);
                BigInteger m2 = new BigInteger(256, rand);
                BigInteger L1 = new BigInteger(512, rand);
                BigInteger L2 = new BigInteger(512, rand);
                assertTrue(m1.compareTo(m2) != 0, "m1 != m2");
                ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSA_F_AM_2004.Native.HashValue h1 = new ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSA_F_AM_2004.Native.HashValue();
                ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSA_F_AM_2004.Native.HashValue h2 = new ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSA_F_AM_2004.Native.HashValue();
                ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSA_F_AM_2004.Native.Randomness r1 = new ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSA_F_AM_2004.Native.Randomness();
                ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSA_F_AM_2004.Native.Randomness r2 = new ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSA_F_AM_2004.Native.Randomness();
                ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSA_F_AM_2004.Native.Randomness r1_p = new ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSA_F_AM_2004.Native.Randomness();
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
                ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSANN_F_AM_2004.Native scheme = new ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSANN_F_AM_2004.Native();
                ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSANN_F_AM_2004.Native.PublicKey pk = new ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSANN_F_AM_2004.Native.PublicKey();
                ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSANN_F_AM_2004.Native.SecretKey sk = new ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSANN_F_AM_2004.Native.SecretKey();
                scheme.KeyGen(pk, sk, 512);
                BigInteger m1 = new BigInteger(256, rand);
                BigInteger m2 = new BigInteger(256, rand);
                BigInteger L1 = new BigInteger(512, rand);
                BigInteger L2 = new BigInteger(512, rand);
                assertTrue(m1.compareTo(m2) != 0, "m1 != m2");
                ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSANN_F_AM_2004.Native.HashValue h1 = new ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSANN_F_AM_2004.Native.HashValue();
                ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSANN_F_AM_2004.Native.HashValue h2 = new ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSANN_F_AM_2004.Native.HashValue();
                ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSANN_F_AM_2004.Native.Randomness r1 = new ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSANN_F_AM_2004.Native.Randomness();
                ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSANN_F_AM_2004.Native.Randomness r2 = new ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSANN_F_AM_2004.Native.Randomness();
                ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSANN_F_AM_2004.Native.Randomness r1_p = new ChameleonHash.CH.DEPRECATED.CH_KEF_MH_RSANN_F_AM_2004.Native.Randomness();
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
            @ParameterizedTest(name = "test curve {0} group {1}")
            @MethodSource("CHTest#GetPBCCartesianProduct")
            void JPBCTest(curve.PBC curve, Group group) {
                ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC scheme = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC();
                ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.PublicParam pp = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.PublicParam(curve, group);
                ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.PublicKey pk = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.PublicKey();
                ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.SecretKey sk = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.SecretKey();
                scheme.KeyGen(pk, sk, pp);
                Element m1 = pp.GP.GetZrElement();
                Element m2 = pp.GP.GetZrElement();
                Element L1 = pp.GP.GetZrElement();
                Element L2 = pp.GP.GetZrElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");

                ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.HashValue h1 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.HashValue();
                ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.HashValue h2 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.HashValue();
                ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.Randomness r1 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.Randomness();
                ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.Randomness r2 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.Randomness();
                ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.Randomness r1_p = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.Randomness();
                scheme.Hash(h1, r1, pp, pk, L1, m1);
                assertTrue(scheme.Check(h1, r1, pp, pk, L1, m1), "H(L1, m1) valid");
                assertFalse(scheme.Check(h1, r1, pp, pk, L2, m1), "not H(L2, m1)");
                scheme.Hash(h2, r2, pp, pk, L2, m2);
                assertTrue(scheme.Check(h2, r2, pp, pk, L2, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, pp, pk, L1, m2), "not H(L1, m2)");

                assertFalse(scheme.Check(h1, r1, pp, pk, L2, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pp, pk, L1, m1), "not H(m2)");

                scheme.Adapt(r1_p, h1, r1, pp, pk, sk, L1, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pp, pk, L1, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h1, r1_p, pp, pk, L2, m2), "not L2");

                scheme.Adapt(r1_p, h2, r2, pp, pk, sk, L2, m2, m1);
                assertTrue(scheme.Check(h2, r1_p, pp, pk, L2, m1), "Adapt(m1) valid");
                assertFalse(scheme.Check(h2, r1_p, pp, pk, L1, m1), "not L1");
            }

            @DisplayName("test PBC Pairing impl")
            @ParameterizedTest(name = "test curve {0}")
            @EnumSource(names = {"A", "A1", "E"})
            void JPBCPairingTest(curve.PBC curve) {
                ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC_pairing scheme = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC_pairing();
                ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC_pairing.PublicParam pp = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC_pairing.PublicParam(curve);
                ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC_pairing.PublicKey pk = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC_pairing.PublicKey();
                ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC_pairing.SecretKey sk = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC_pairing.SecretKey();
                scheme.KeyGen(pk, sk, pp);
                Element m1 = pp.GP.GetZrElement();
                Element m2 = pp.GP.GetZrElement();
                Element L1 = pp.GP.GetZrElement();
                Element L2 = pp.GP.GetZrElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");

                ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC_pairing.HashValue h1 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC_pairing.HashValue();
                ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC_pairing.HashValue h2 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC_pairing.HashValue();
                ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC_pairing.Randomness r1 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC_pairing.Randomness();
                ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC_pairing.Randomness r2 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC_pairing.Randomness();
                ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC_pairing.Randomness r1_p = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC_pairing.Randomness();
                scheme.Hash(h1, r1, pp, pk, L1, m1);
                assertTrue(scheme.Check(h1, r1, pp, pk, L1, m1), "H(L1, m1) valid");
                assertFalse(scheme.Check(h1, r1, pp, pk, L2, m1), "not H(L2, m1)");
                scheme.Hash(h2, r2, pp, pk, L2, m2);
                assertTrue(scheme.Check(h2, r2, pp, pk, L2, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, pp, pk, L1, m2), "not H(L1, m2)");

                assertFalse(scheme.Check(h1, r1, pp, pk, L2, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pp, pk, L1, m1), "not H(m2)");

                scheme.Adapt(r1_p, r1, pp, pk, sk, L1, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pp, pk, L1, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h1, r1_p, pp, pk, L2, m2), "not L2");

                scheme.Adapt(r1_p, r2, pp, pk, sk, L2, m2, m1);
                assertTrue(scheme.Check(h2, r1_p, pp, pk, L2, m1), "Adapt(m1) valid");
                assertFalse(scheme.Check(h2, r1_p, pp, pk, L1, m1), "not L1");
            }

            @DisplayName("test MCL impl")
            @ParameterizedTest(name = "test curve {0}")
            // UnitTest.CurveLib.BadCaseTest#MCL_Bad_Case#Case2
            @EnumSource(names = {"BN254", "BLS12_381"})
//            @EnumSource(MCL.class)
            void MCLTest(MCL curve) {
                Func.MCLInit(curve);
                {
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1 scheme = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.PublicParam pp = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.PublicParam();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.PublicKey pk = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.PublicKey();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.SecretKey sk = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    Fr m1 = new Fr();
                    pp.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    pp.GP.GetZrElement(m2);
                    Fr L1 = new Fr();
                    pp.GP.GetZrElement(L1);
                    Fr L2 = new Fr();
                    pp.GP.GetZrElement(L2);
                    assertFalse(m1.equals(m2), "m1 != m2");

                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.HashValue h1 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.HashValue();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.HashValue h2 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.HashValue();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.Randomness r1 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.Randomness();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.Randomness r2 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.Randomness();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.Randomness r1_p = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.Randomness();
                    scheme.Hash(h1, r1, pp, pk, L1, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, L1, m1), "H(L1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, pp, pk, L2, m1), "not H(L2, m1)");
                    scheme.Hash(h2, r2, pp, pk, L2, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, L2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pp, pk, L1, m2), "not H(L1, m2)");

                    assertFalse(scheme.Check(h1, r1, pp, pk, L2, m2), "not H(m1)");
                    assertFalse(scheme.Check(h2, r2, pp, pk, L1, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, pp, pk, sk, L1, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, L1, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, L2, m2), "not L2");

                    scheme.Adapt(r1_p, h2, r2, pp, pk, sk, L2, m2, m1);
                    assertTrue(scheme.Check(h2, r1_p, pp, pk, L2, m1), "Adapt(m1) valid");
                    assertFalse(scheme.Check(h2, r1_p, pp, pk, L1, m1), "not L1");
                }
                {
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2 scheme = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.PublicParam pp = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.PublicParam();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.PublicKey pk = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.PublicKey();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.SecretKey sk = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    Fr m1 = new Fr();
                    pp.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    pp.GP.GetZrElement(m2);
                    Fr L1 = new Fr();
                    pp.GP.GetZrElement(L1);
                    Fr L2 = new Fr();
                    pp.GP.GetZrElement(L2);
                    assertFalse(m1.equals(m2), "m1 != m2");

                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.HashValue h1 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.HashValue();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.HashValue h2 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.HashValue();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.Randomness r1 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.Randomness();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.Randomness r2 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.Randomness();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.Randomness r1_p = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.Randomness();
                    scheme.Hash(h1, r1, pp, pk, L1, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, L1, m1), "H(L1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, pp, pk, L2, m1), "not H(L2, m1)");
                    scheme.Hash(h2, r2, pp, pk, L2, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, L2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pp, pk, L1, m2), "not H(L1, m2)");

                    assertFalse(scheme.Check(h1, r1, pp, pk, L2, m2), "not H(m1)");
                    assertFalse(scheme.Check(h2, r2, pp, pk, L1, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, pp, pk, sk, L1, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, L1, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, L2, m2), "not L2");

                    scheme.Adapt(r1_p, h2, r2, pp, pk, sk, L2, m2, m1);
                    assertTrue(scheme.Check(h2, r1_p, pp, pk, L2, m1), "Adapt(m1) valid");
                    assertFalse(scheme.Check(h2, r1_p, pp, pk, L1, m1), "not L1");
                }
                {
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT scheme = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.PublicParam pp = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.PublicParam();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.PublicKey pk = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.PublicKey();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.SecretKey sk = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    Fr m1 = new Fr();
                    pp.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    pp.GP.GetZrElement(m2);
                    Fr L1 = new Fr();
                    pp.GP.GetZrElement(L1);
                    Fr L2 = new Fr();
                    pp.GP.GetZrElement(L2);
                    assertFalse(m1.equals(m2), "m1 != m2");

                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.HashValue h1 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.HashValue();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.HashValue h2 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.HashValue();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.Randomness r1 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.Randomness();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.Randomness r2 = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.Randomness();
                    ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.Randomness r1_p = new ChameleonHash.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.Randomness();
                    scheme.Hash(h1, r1, pp, pk, L1, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, L1, m1), "H(L1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, pp, pk, L2, m1), "not H(L2, m1)");
                    scheme.Hash(h2, r2, pp, pk, L2, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, L2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pp, pk, L1, m2), "not H(L1, m2)");

                    assertFalse(scheme.Check(h1, r1, pp, pk, L2, m2), "not H(m1)");
                    assertFalse(scheme.Check(h2, r2, pp, pk, L1, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, pp, pk, sk, L1, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, L1, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, L2, m2), "not L2");

                    scheme.Adapt(r1_p, h2, r2, pp, pk, sk, L2, m2, m1);
                    assertTrue(scheme.Check(h2, r1_p, pp, pk, L2, m1), "Adapt(m1) valid");
                    assertFalse(scheme.Check(h2, r1_p, pp, pk, L1, m1), "not L1");
                }
            }
        }

    }

    @DisplayName("test paper 《Chameleon-Hashes with Ephemeral Trapdoors And Applications to Invisible Sanitizable Signatures》")
    @Nested
    class ChameleonHashesWithEphemeralTrapdoorsAndApplicationsToInvisibleSanitizableSignaturesTest {
        @DisplayName("test CH_CDK_2017")
        @Nested
        class CH_CDK_2017_Test {
            @DisplayName("test Native impl")
            @ParameterizedTest(name = "test lambda = {0}")
            @ValueSource(ints = {256, 512, 1024, 2048})
            void NativeTest(int lambda) {
                Random rand = new Random();
                ChameleonHash.CH.DEPRECATED.CH_CDK_2017.Native scheme = new ChameleonHash.CH.DEPRECATED.CH_CDK_2017.Native(lambda);
                ChameleonHash.CH.DEPRECATED.CH_CDK_2017.Native.PublicKey pk = new ChameleonHash.CH.DEPRECATED.CH_CDK_2017.Native.PublicKey();
                ChameleonHash.CH.DEPRECATED.CH_CDK_2017.Native.SecretKey sk = new ChameleonHash.CH.DEPRECATED.CH_CDK_2017.Native.SecretKey();
                scheme.KeyGen(pk, sk);
                BigInteger m1 = new BigInteger(lambda, rand);
                BigInteger m2 = new BigInteger(lambda, rand);
                BigInteger l1 = new BigInteger(lambda, rand);
                BigInteger l2 = new BigInteger(lambda, rand);
                ChameleonHash.CH.DEPRECATED.CH_CDK_2017.Native.HashValue h1 = new ChameleonHash.CH.DEPRECATED.CH_CDK_2017.Native.HashValue();
                ChameleonHash.CH.DEPRECATED.CH_CDK_2017.Native.HashValue h2 = new ChameleonHash.CH.DEPRECATED.CH_CDK_2017.Native.HashValue();
                ChameleonHash.CH.DEPRECATED.CH_CDK_2017.Native.Randomness r1 = new ChameleonHash.CH.DEPRECATED.CH_CDK_2017.Native.Randomness();
                ChameleonHash.CH.DEPRECATED.CH_CDK_2017.Native.Randomness r1_p = new ChameleonHash.CH.DEPRECATED.CH_CDK_2017.Native.Randomness();
                ChameleonHash.CH.DEPRECATED.CH_CDK_2017.Native.Randomness r2 = new ChameleonHash.CH.DEPRECATED.CH_CDK_2017.Native.Randomness();
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
                Native scheme = new Native(lambda);
                Native.PublicKey pk = new Native.PublicKey();
                Native.SecretKey sk = new Native.SecretKey();
                scheme.KeyGen(pk, sk);
                String m1 = "WCjrCK";
                String m2 = "123";
                Native.HashValue h1 = new Native.HashValue();
                Native.HashValue h2 = new Native.HashValue();
                Native.Randomness r1 = new Native.Randomness();
                Native.Randomness r1_p = new Native.Randomness();
                Native.Randomness r2 = new Native.Randomness();
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
                ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native scheme = new ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native(lambda);
                ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native.PublicKey pk = new ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native.PublicKey();
                ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native.SecretKey sk = new ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native.SecretKey();
                scheme.KeyGen(pk, sk);
                BigInteger m1 = new BigInteger(lambda, rand);
                BigInteger m2 = new BigInteger(lambda, rand);
                assertTrue(m1.compareTo(m2) != 0, "m1 != m2");
                ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native.HashValue h1 = new ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native.HashValue();
                ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native.HashValue h2 = new ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native.HashValue();
                ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native.Randomness r1 = new ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native.Randomness();
                ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native.Randomness r1_p = new ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native.Randomness();
                ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native.Randomness r2 = new ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native.Randomness();
                ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native.ETrapdoor etd1 = new ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native.ETrapdoor();
                ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native.ETrapdoor etd2 = new ChameleonHash.CH.DEPRECATED.CHET_RSA_CDK_2017.Native.ETrapdoor();
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

    @DisplayName("test paper 《Bringing Order to Chaos：The Case of Collision-Resistant Chameleon-Hashes》")
    @Nested
    class BringingOrderToChaosTheCaseOfCollisionResistantChameleonHashesTest {
        @DisplayName("test CR_CH_DSS_2020")
        @Nested
        class CR_CH_DSS_2020_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} group {1}")
            @MethodSource("CHTest#GetPBCCartesianProduct")
            void JPBCTest(curve.PBC curve, Group group) {
                ChameleonHash.CH.CR_CH_DSS_2020.PBC scheme = new ChameleonHash.CH.CR_CH_DSS_2020.PBC();
                ChameleonHash.CH.CR_CH_DSS_2020.PBC.PublicParam pp = new ChameleonHash.CH.CR_CH_DSS_2020.PBC.PublicParam(curve, group);
                ChameleonHash.CH.CR_CH_DSS_2020.PBC.PublicKey pk = new ChameleonHash.CH.CR_CH_DSS_2020.PBC.PublicKey();
                ChameleonHash.CH.CR_CH_DSS_2020.PBC.SecretKey sk = new ChameleonHash.CH.CR_CH_DSS_2020.PBC.SecretKey();
                scheme.KeyGen(pk, sk, pp);
                Element m1 = pp.GP.GetGElement();
                Element m2 = pp.GP.GetGElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");

                ChameleonHash.CH.CR_CH_DSS_2020.PBC.HashValue h1 = new ChameleonHash.CH.CR_CH_DSS_2020.PBC.HashValue();
                ChameleonHash.CH.CR_CH_DSS_2020.PBC.HashValue h2 = new ChameleonHash.CH.CR_CH_DSS_2020.PBC.HashValue();
                ChameleonHash.CH.CR_CH_DSS_2020.PBC.Randomness r1 = new ChameleonHash.CH.CR_CH_DSS_2020.PBC.Randomness();
                ChameleonHash.CH.CR_CH_DSS_2020.PBC.Randomness r2 = new ChameleonHash.CH.CR_CH_DSS_2020.PBC.Randomness();
                ChameleonHash.CH.CR_CH_DSS_2020.PBC.Randomness r1_p = new ChameleonHash.CH.CR_CH_DSS_2020.PBC.Randomness();
                scheme.Hash(h1, r1, pp, pk, m1);
                assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                scheme.Hash(h2, r2, pp, pk, m2);
                assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                scheme.Adapt(r1_p, h1, r1, pp, pk, sk, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not Adapt(m1)");
            }

            @DisplayName("test MCL impl")
            @ParameterizedTest(name = "test curve {0}")
            // UnitTest.CurveLib.BadCaseTest#MCL_Bad_Case#Case2
            @EnumSource(names = {"BN254", "BLS12_381"})
            void MCLTest(MCL curve) {
                Func.MCLInit(curve);
                {
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_G1 scheme = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_G1();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_G1.PublicParam pp = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_G1.PublicParam();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_G1.PublicKey pk = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_G1.PublicKey();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_G1.SecretKey sk = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_G1.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    G1 m1 = new G1();
                    pp.GP.GetGElement(m1);
                    G1 m2 = new G1();
                    pp.GP.GetGElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");

                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_G1.HashValue h1 = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_G1.HashValue();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_G1.HashValue h2 = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_G1.HashValue();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_G1.Randomness r1 = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_G1.Randomness();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_G1.Randomness r2 = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_G1.Randomness();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_G1.Randomness r1_p = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_G1.Randomness();
                    scheme.Hash(h1, r1, pp, pk, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                    scheme.Hash(h2, r2, pp, pk, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, pp, pk, sk, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not Adapt(m1)");
                }
                {
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_G2 scheme = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_G2();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_G2.PublicParam pp = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_G2.PublicParam();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_G2.PublicKey pk = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_G2.PublicKey();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_G2.SecretKey sk = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_G2.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    G2 m1 = new G2();
                    pp.GP.GetGElement(m1);
                    G2 m2 = new G2();
                    pp.GP.GetGElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");

                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_G2.HashValue h1 = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_G2.HashValue();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_G2.HashValue h2 = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_G2.HashValue();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_G2.Randomness r1 = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_G2.Randomness();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_G2.Randomness r2 = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_G2.Randomness();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_G2.Randomness r1_p = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_G2.Randomness();
                    scheme.Hash(h1, r1, pp, pk, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                    scheme.Hash(h2, r2, pp, pk, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, pp, pk, sk, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not Adapt(m1)");
                }
                {
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_GT scheme = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_GT();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_GT.PublicParam pp = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_GT.PublicParam();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_GT.PublicKey pk = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_GT.PublicKey();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_GT.SecretKey sk = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_GT.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    GT m1 = new GT();
                    pp.GP.GetGElement(m1);
                    GT m2 = new GT();
                    pp.GP.GetGElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");

                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_GT.HashValue h1 = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_GT.HashValue();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_GT.HashValue h2 = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_GT.HashValue();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_GT.Randomness r1 = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_GT.Randomness();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_GT.Randomness r2 = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_GT.Randomness();
                    ChameleonHash.CH.CR_CH_DSS_2020.MCL_GT.Randomness r1_p = new ChameleonHash.CH.CR_CH_DSS_2020.MCL_GT.Randomness();
                    scheme.Hash(h1, r1, pp, pk, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                    scheme.Hash(h2, r2, pp, pk, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, pp, pk, sk, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not Adapt(m1)");
                }
            }
        }
    }
}
