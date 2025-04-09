import base.BinaryTree.PBC;
import com.herumi.mcl.G1;
import com.herumi.mcl.G2;
import curve.MCL;
import it.unisa.dia.gas.jpbc.Element;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import utils.BooleanFormulaParser;
import utils.Func;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static utils.Func.InitialLib;

public class ABETest {
    public static Stream<Arguments> GetPBCInvert() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a -> Stream.of(Arguments.of(a, false), Arguments.of(a, true)));
    }

    public static Stream<Arguments> GetPBCSymmAuth() {
        return Stream.of(curve.PBC.A, curve.PBC.A1, curve.PBC.E).flatMap(a ->
                Stream.of(16, 32, 64).flatMap(b -> Stream.of(Arguments.of(a, b))));
    }

//    public static Stream<Arguments> GetPBCInvertN() {
//        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a ->
//                Stream.of(16, 32, 64).flatMap(b ->
//                        Stream.of(Arguments.of(a, false, b), Arguments.of(a, true, b))
//                )
//        );
//    }

    public static Stream<Arguments> GetPBCInvertNType() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a ->
                Stream.of(16, 32, 64).flatMap(b ->
                        Stream.of(
                                Arguments.of(a, false, b, ABE.RABE.PBC.TYPE.XNM_2021), Arguments.of(a, true, b, ABE.RABE.PBC.TYPE.XNM_2021),
                                Arguments.of(a, false, b, ABE.RABE.PBC.TYPE.TMM_2022), Arguments.of(a, true, b, ABE.RABE.PBC.TYPE.TMM_2022)
                        )
                )
        );
    }

    public static Stream<Arguments> GetMCLInvertNType() {
        return Stream.of(MCL.BN254, MCL.BLS12_381).flatMap(a ->
                Stream.of(16, 32, 64).flatMap(b ->
                        Stream.of(
                                Arguments.of(a, b, ABE.RABE.MCL.TYPE.XNM_2021), Arguments.of(a, b, ABE.RABE.MCL.TYPE.TMM_2022)
                        )
                )
        );
    }

    public static Stream<Arguments> GetMCLSwapInvertNType() {
        return Stream.of(MCL.BN254, MCL.BLS12_381).flatMap(a ->
                Stream.of(16, 32, 64).flatMap(b ->
                        Stream.of(
                                Arguments.of(a, b, ABE.RABE.MCL_swap.TYPE.XNM_2021), Arguments.of(a, b, ABE.RABE.MCL_swap.TYPE.TMM_2022)
                        )
                )
        );
    }

    @BeforeEach
    void initTest() {
        InitialLib();
    }

    @DisplayName("test paper 《FAME: Fast Attribute-based Message Encryption》")
    @Nested
    class FAMEFastAttributeBasedMessageEncryptionTest {
        @DisplayName("test FAME")
        @Nested
        class FAME_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} swap_G1G2 {1}")
            @MethodSource("ABETest#GetPBCInvert")
            void JPBCTest(curve.PBC curve, boolean swap_G1G2) {
                ABE.FAME.PBC scheme = new ABE.FAME.PBC();
                ABE.FAME.PBC.PublicParam SP = new ABE.FAME.PBC.PublicParam(curve, swap_G1G2);
                ABE.FAME.PBC.MasterPublicKey mpk = new ABE.FAME.PBC.MasterPublicKey();
                ABE.FAME.PBC.MasterSecretKey msk = new ABE.FAME.PBC.MasterSecretKey();
                scheme.SetUp(mpk, msk, SP);

                base.LSSS.PBC LSSS = new base.LSSS.PBC();
                base.LSSS.PBC.Matrix MSP = new base.LSSS.PBC.Matrix(SP.GP.Zr);
                BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                LSSS.GenLSSSMatrices(MSP, pl, "(A1|(A2|A3))&(DDDD|(BB&CCC))");
                for (int i = 0;i < MSP.M.length; ++i) System.out.println(Arrays.toString(MSP.M[i]));

                BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();

                S1.attrs.add("A1");
                S1.attrs.add("DDDD");

                S2.attrs.add("BB");
                S2.attrs.add("CCC");

                ABE.FAME.PBC.SecretKey sk1 = new ABE.FAME.PBC.SecretKey();
                scheme.KeyGen(sk1, SP, mpk, msk, S1);
                ABE.FAME.PBC.SecretKey sk2 = new ABE.FAME.PBC.SecretKey();
                scheme.KeyGen(sk2, SP, mpk, msk, S2);

                ABE.FAME.PBC.PlainText m1 = new ABE.FAME.PBC.PlainText(SP.GP.GetGTElement());
                ABE.FAME.PBC.PlainText m2 = new ABE.FAME.PBC.PlainText(SP.GP.GetGTElement());
                ABE.FAME.PBC.PlainText m3 = new ABE.FAME.PBC.PlainText(SP.GP.GetGTElement());
                ABE.FAME.PBC.CipherText ct1 = new ABE.FAME.PBC.CipherText();
                ABE.FAME.PBC.CipherText ct2 = new ABE.FAME.PBC.CipherText();

                scheme.Encrypt(ct1, SP, mpk, MSP, m1);
                scheme.Decrypt(m3, SP, MSP, ct1, sk1);
                assertTrue(m3.isEqual(m1), "decrypt(sk1, ct1) != m1");

                scheme.Encrypt(ct2, SP, mpk, MSP, m2);
                scheme.Decrypt(m3, SP, MSP, ct2, sk1);
                assertTrue(m3.isEqual(m2), "decrypt(sk1, ct2) != m2");

                scheme.Decrypt(m3, SP, MSP, ct1, sk2);
                assertFalse(m3.isEqual(m1), "decrypt(sk2, ct1) invalid");
                assertFalse(m3.isEqual(m2), "decrypt(sk2, ct1) invalid");
            }

            @DisplayName("test MCL impl")
            @ParameterizedTest(name = "test curve {0}")
            // BadCaseTest#MCL_Bad_Case#Case2
            @EnumSource(names = {"BN254", "BLS12_381"})
            void MCLTest(MCL curve) {
                Func.MCLInit(curve);
                {
                    ABE.FAME.MCL scheme = new ABE.FAME.MCL();
                    ABE.FAME.MCL.PublicParam SP = new ABE.FAME.MCL.PublicParam();
                    ABE.FAME.MCL.MasterPublicKey mpk = new ABE.FAME.MCL.MasterPublicKey();
                    ABE.FAME.MCL.MasterSecretKey msk = new ABE.FAME.MCL.MasterSecretKey();
                    scheme.SetUp(mpk, msk);

                    base.LSSS.MCL LSSS = new base.LSSS.MCL();
                    base.LSSS.MCL.Matrix MSP = new base.LSSS.MCL.Matrix();
                    BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                    LSSS.GenLSSSMatrices(MSP, pl, "(A1|(A2|A3))&(DDDD|(BB&CCC))");

                    BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                    BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();

                    S1.attrs.add("A1");
                    S1.attrs.add("DDDD");

                    S2.attrs.add("BB");
                    S2.attrs.add("CCC");

                    ABE.FAME.MCL.SecretKey sk1 = new ABE.FAME.MCL.SecretKey();
                    scheme.KeyGen(sk1, SP, mpk, msk, S1);
                    ABE.FAME.MCL.SecretKey sk2 = new ABE.FAME.MCL.SecretKey();
                    scheme.KeyGen(sk2, SP, mpk, msk, S2);

                    ABE.FAME.MCL.PlainText m1 = new ABE.FAME.MCL.PlainText();
                    ABE.FAME.MCL.PlainText m2 = new ABE.FAME.MCL.PlainText();
                    ABE.FAME.MCL.PlainText m3 = new ABE.FAME.MCL.PlainText();
                    ABE.FAME.MCL.CipherText ct1 = new ABE.FAME.MCL.CipherText();
                    ABE.FAME.MCL.CipherText ct2 = new ABE.FAME.MCL.CipherText();

                    scheme.Encrypt(ct1, SP, mpk, MSP, m1);
                    scheme.Decrypt(m3, MSP, ct1, sk1);
                    assertTrue(m3.isEqual(m1), "decrypt(sk1, ct1) != m1");

                    scheme.Encrypt(ct2, SP, mpk, MSP, m2);
                    scheme.Decrypt(m3, MSP, ct2, sk1);
                    assertTrue(m3.isEqual(m2), "decrypt(sk1, ct2) != m2");

                    scheme.Decrypt(m3, MSP, ct1, sk2);
                    assertFalse(m3.isEqual(m1), "decrypt(sk2, ct1) invalid");
                    assertFalse(m3.isEqual(m2), "decrypt(sk2, ct1) invalid");
                }
                {
                    ABE.FAME.MCL_swap scheme = new ABE.FAME.MCL_swap();
                    ABE.FAME.MCL_swap.PublicParam SP = new ABE.FAME.MCL_swap.PublicParam();
                    ABE.FAME.MCL_swap.MasterPublicKey mpk = new ABE.FAME.MCL_swap.MasterPublicKey();
                    ABE.FAME.MCL_swap.MasterSecretKey msk = new ABE.FAME.MCL_swap.MasterSecretKey();
                    scheme.SetUp(mpk, msk);

                    base.LSSS.MCL LSSS = new base.LSSS.MCL();
                    base.LSSS.MCL.Matrix MSP = new base.LSSS.MCL.Matrix();
                    BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                    LSSS.GenLSSSMatrices(MSP, pl, "(A1|(A2|A3))&(DDDD|(BB&CCC))");

                    BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                    BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();

                    S1.attrs.add("A1");
                    S1.attrs.add("DDDD");

                    S2.attrs.add("BB");
                    S2.attrs.add("CCC");

                    ABE.FAME.MCL_swap.SecretKey sk1 = new ABE.FAME.MCL_swap.SecretKey();
                    scheme.KeyGen(sk1, SP, mpk, msk, S1);
                    ABE.FAME.MCL_swap.SecretKey sk2 = new ABE.FAME.MCL_swap.SecretKey();
                    scheme.KeyGen(sk2, SP, mpk, msk, S2);

                    ABE.FAME.MCL_swap.PlainText m1 = new ABE.FAME.MCL_swap.PlainText();
                    ABE.FAME.MCL_swap.PlainText m2 = new ABE.FAME.MCL_swap.PlainText();
                    ABE.FAME.MCL_swap.PlainText m3 = new ABE.FAME.MCL_swap.PlainText();
                    ABE.FAME.MCL_swap.CipherText ct1 = new ABE.FAME.MCL_swap.CipherText();
                    ABE.FAME.MCL_swap.CipherText ct2 = new ABE.FAME.MCL_swap.CipherText();

                    scheme.Encrypt(ct1, SP, mpk, MSP, m1);
                    scheme.Decrypt(m3, MSP, ct1, sk1);
                    assertTrue(m3.isEqual(m1), "decrypt(sk1, ct1) != m1");

                    scheme.Encrypt(ct2, SP, mpk, MSP, m2);
                    scheme.Decrypt(m3, MSP, ct2, sk1);
                    assertTrue(m3.isEqual(m2), "decrypt(sk1, ct2) != m2");

                    scheme.Decrypt(m3, MSP, ct1, sk2);
                    assertFalse(m3.isEqual(m1), "decrypt(sk2, ct1) invalid");
                    assertFalse(m3.isEqual(m2), "decrypt(sk2, ct1) invalid");
                }
            }
        }
    }

    @DisplayName("test paper 《Efficient Statically-Secure Large-Universe Multi-Authority Attribute-Based Encryption》")
    @Nested
    class EfficientStaticallySecureLargeUniverseMultiAuthorityAttributeBasedEncryptionTest {
        @DisplayName("test MA_ABE")
        @Nested
        class MA_ABE_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} author number {1}")
            @MethodSource("ABETest#GetPBCSymmAuth")
            void JPBCTest(curve.PBC curve, int auth_num) {
                ABE.MA_ABE.PBC scheme = new ABE.MA_ABE.PBC();
                ABE.MA_ABE.PBC.PublicParam GP = new ABE.MA_ABE.PBC.PublicParam(curve);

                base.LSSS.PBC LSSS = new base.LSSS.PBC();
                base.LSSS.PBC.Matrix MSP = new base.LSSS.PBC.Matrix(GP.GP.Zr);
                BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                LSSS.GenLSSSMatrices(MSP, pl, "(A|FF)&(DDDD|(BB&CCC))");

                String GID1 = "WCjrCK";
                String GID2 = "gid2";
                ABE.MA_ABE.PBC.SecretKey SK1 = new ABE.MA_ABE.PBC.SecretKey();
                ABE.MA_ABE.PBC.SecretKey SK2 = new ABE.MA_ABE.PBC.SecretKey();

                ABE.MA_ABE.PBC.Authority[] auths = new ABE.MA_ABE.PBC.Authority[auth_num];
                for (int i = 0; i < auth_num; ++i) auths[i] = new ABE.MA_ABE.PBC.Authority("theta_a_" + i);
                ABE.MA_ABE.PBC.PublicKeyGroup PKG = new ABE.MA_ABE.PBC.PublicKeyGroup();
                for (int i = 0; i < auth_num; ++i) scheme.AuthSetup(auths[i], GP);
                auths[0].control_attr.add("A");
                auths[1].control_attr.add("BB");
                auths[2].control_attr.add("CCC");
                auths[3].control_attr.add("DDDD");
                auths[4].control_attr.add("E");
                auths[5].control_attr.add("FF");

                for (int i = 0; i < auth_num; ++i) PKG.AddPK(auths[i]);

                ABE.MA_ABE.PBC.SecretKeyGroup SKG1 = new ABE.MA_ABE.PBC.SecretKeyGroup();
                ABE.MA_ABE.PBC.SecretKeyGroup SKG3 = new ABE.MA_ABE.PBC.SecretKeyGroup();
                scheme.KeyGen(auths[0], SK1, "A", GP, GID1);
                SKG1.AddSK(SK1);
                SKG3.AddSK(SK1);
                scheme.KeyGen(auths[3], SK1, "DDDD", GP, GID1);
                SKG1.AddSK(SK1);
                scheme.KeyGen(auths[4], SK1, "E", GP, GID1);
                SKG1.AddSK(SK1);

                ABE.MA_ABE.PBC.SecretKeyGroup SKG2 = new ABE.MA_ABE.PBC.SecretKeyGroup();
                scheme.KeyGen(auths[1], SK2, "BB", GP, GID2);
                SKG2.AddSK(SK2);
                SKG3.AddSK(SK2);
                scheme.KeyGen(auths[2], SK2, "CCC", GP, GID2);
                SKG2.AddSK(SK2);
                SKG3.AddSK(SK2);
                scheme.KeyGen(auths[5], SK2, "FF", GP, GID2);
                SKG2.AddSK(SK2);

                ABE.MA_ABE.PBC.PlainText m1 = new ABE.MA_ABE.PBC.PlainText(GP.GP.GetGTElement());
                ABE.MA_ABE.PBC.PlainText m2 = new ABE.MA_ABE.PBC.PlainText(GP.GP.GetGTElement());
                ABE.MA_ABE.PBC.PlainText m3 = new ABE.MA_ABE.PBC.PlainText(GP.GP.GetGTElement());

                ABE.MA_ABE.PBC.CipherText c1 = new ABE.MA_ABE.PBC.CipherText();
                ABE.MA_ABE.PBC.CipherText c2 = new ABE.MA_ABE.PBC.CipherText();

                scheme.Encrypt(c1, GP, PKG, MSP, m1);
                scheme.Encrypt(c2, GP, PKG, MSP, m2);

                scheme.Decrypt(m3, GP, SKG1, MSP, c1);
                assertTrue(m3.isEqual(m1), "decrypt(c1) = m1");
                assertFalse(m3.isEqual(m2), "decrypt(c1) != m2");

                scheme.Decrypt(m3, GP, SKG2, MSP, c2);
                assertTrue(m3.isEqual(m2), "decrypt(c2) = m2");

                scheme.Decrypt(m3, GP, SKG3, MSP, c1);
                assertFalse(m3.isEqual(m1), "decrypt invalid");
                assertFalse(m3.isEqual(m2), "decrypt invalid");
            }
        }
    }



    @DisplayName("test paper 《Revocable Policy-Based Chameleon Hash》")
    @Nested
    class RevocablPolicyBasedChameleonHashTest {
        @DisplayName("test RABE")
        @Nested
        class RABE_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} swap_G1G2 {1} with leaf node size = {2} RABE type = {3}")
            @MethodSource("ABETest#GetPBCInvertNType")
            void JPBCTest(curve.PBC curve, boolean swap_G1G2, int n, ABE.RABE.PBC.TYPE t) {
                ABE.RABE.PBC scheme = new ABE.RABE.PBC();
                ABE.RABE.PBC.PublicParam SP = new ABE.RABE.PBC.PublicParam(t, curve, swap_G1G2);
                ABE.RABE.PBC.MasterPublicKey mpk = new ABE.RABE.PBC.MasterPublicKey();
                ABE.RABE.PBC.MasterSecretKey msk = new ABE.RABE.PBC.MasterSecretKey();
                scheme.SetUp(mpk, msk, SP);

                base.BinaryTree.PBC BT = new PBC(n);
                base.BinaryTree.PBC.RevokeList rl = new base.BinaryTree.PBC.RevokeList();

                base.LSSS.PBC LSSS = new base.LSSS.PBC();
                base.LSSS.PBC.Matrix MSP = new base.LSSS.PBC.Matrix(SP.GP.Zr);
                BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

                BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                S1.attrs.add("A");
                S1.attrs.add("DDDD");

                BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();
                S2.attrs.add("BB");
                S2.attrs.add("CCC");

                BooleanFormulaParser.AttributeList S3 = new BooleanFormulaParser.AttributeList();
                S3.attrs.add("A");
                S3.attrs.add("BB");
                S3.attrs.add("CCC");

                Element id1 = SP.GP.GetZrElement();
                ABE.RABE.PBC.SecretKey sk1 = new ABE.RABE.PBC.SecretKey();
                scheme.KeyGen(sk1, BT, SP, mpk, msk, S1, id1);

                Element id2 = SP.GP.GetZrElement();
                ABE.RABE.PBC.SecretKey sk2 = new ABE.RABE.PBC.SecretKey();
                scheme.KeyGen(sk2, BT, SP, mpk, msk, S2, id2);

                ABE.RABE.PBC.SecretKey sk3 = new ABE.RABE.PBC.SecretKey();
                scheme.KeyGen(sk3, BT, SP, mpk, msk, S3, id1);

                scheme.Revoke(rl, id1, 10);
                scheme.Revoke(rl, id2, 100);

                ABE.RABE.PBC.PlainText m1 = new ABE.RABE.PBC.PlainText();
                ABE.RABE.PBC.PlainText m2 = new ABE.RABE.PBC.PlainText();
                ABE.RABE.PBC.PlainText m3 = new ABE.RABE.PBC.PlainText();
                if(t == ABE.RABE.PBC.TYPE.XNM_2021) {
//                    m1.m = SP.GP.GetGTElement();
                    m1.m = SP.GP.GT.newOneElement().getImmutable();
                    m2.m = SP.GP.GetGTElement();
                    m3.m = SP.GP.GetGTElement();
                } else if(t == ABE.RABE.PBC.TYPE.TMM_2022) {
                    m1.m = SP.GP.GetZrElement();
                    m2.m = SP.GP.GetZrElement();
                    m3.m = SP.GP.GetZrElement();
                }
                ABE.RABE.PBC.CipherText ct1 = new ABE.RABE.PBC.CipherText();
                ABE.RABE.PBC.CipherText ct2 = new ABE.RABE.PBC.CipherText();

                scheme.Encrypt(ct1, SP, mpk, MSP, m1, 5);
                scheme.Encrypt(ct2, SP, mpk, MSP, m2, 50);

                ABE.RABE.PBC.UpdateKey ku1 = new ABE.RABE.PBC.UpdateKey();
                scheme.UpdateKeyGen(ku1, SP, mpk, BT, rl, 5);

                ABE.RABE.PBC.UpdateKey ku2 = new ABE.RABE.PBC.UpdateKey();
                scheme.UpdateKeyGen(ku2, SP, mpk, BT, rl, 50);

                ABE.RABE.PBC.DecryptKey dk_1_1 = new ABE.RABE.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_1_1, SP, mpk, sk1, ku1, BT, rl);

                ABE.RABE.PBC.DecryptKey dk_1_2 = new ABE.RABE.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_1_2, SP, mpk, sk1, ku2, BT, rl);

                ABE.RABE.PBC.DecryptKey dk_2_1 = new ABE.RABE.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_2_1, SP, mpk, sk2, ku1, BT, rl);

                ABE.RABE.PBC.DecryptKey dk_2_2 = new ABE.RABE.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_2_2, SP, mpk, sk2, ku2, BT, rl);

                ABE.RABE.PBC.DecryptKey dk_3_1 = new ABE.RABE.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_3_1, SP, mpk, sk3, ku1, BT, rl);

                ABE.RABE.PBC.DecryptKey dk_3_2 = new ABE.RABE.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_3_2, SP, mpk, sk3, ku2, BT, rl);

                scheme.Decrypt(m3, SP, dk_1_1, MSP, ct1);
                assertTrue(m3.isEqual(m1), "decrypt(dk_1_1, ct1) == m1");

                scheme.Decrypt(m3, SP, dk_2_1, MSP, ct1);
                assertFalse(m3.isEqual(m1), "policy false");

                scheme.Decrypt(m3, SP, dk_3_1, MSP, ct1);
                assertTrue(m3.isEqual(m1), "decrypt(dk_3_1, ct1) == m1");

                scheme.Decrypt(m3, SP, dk_1_1, MSP, ct2);
                assertFalse(m3.isEqual(m2), "different time");

                assertThrows(NullPointerException.class, () -> {
                    scheme.Decrypt(m3, SP, dk_1_2, MSP, ct2);
                    assertFalse(m3.isEqual(m1), "decrypt(dk_1_2, ct1) != m1");
                }, "id1 expired");
            }

            @DisplayName("test MCL impl")
            @ParameterizedTest(name = "test curve {0} with leaf node size = {1} RABE type = {2}")
            @MethodSource("ABETest#GetMCLInvertNType")
            void MCLTest(curve.MCL curve, int n, ABE.RABE.MCL.TYPE t) {
                Func.MCLInit(curve);
                {
                    ABE.RABE.MCL scheme = new ABE.RABE.MCL();
                    ABE.RABE.MCL.PublicParam SP = new ABE.RABE.MCL.PublicParam(t);
                    ABE.RABE.MCL.MasterPublicKey mpk = new ABE.RABE.MCL.MasterPublicKey();
                    ABE.RABE.MCL.MasterSecretKey msk = new ABE.RABE.MCL.MasterSecretKey();
                    scheme.SetUp(mpk, msk);

                    base.BinaryTree.MCL_G1 BT = new base.BinaryTree.MCL_G1(n);
                    base.BinaryTree.MCL_G1.RevokeList rl = new base.BinaryTree.MCL_G1.RevokeList();

                    base.LSSS.MCL LSSS = new base.LSSS.MCL();
                    base.LSSS.MCL.Matrix MSP = new base.LSSS.MCL.Matrix();
                    BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                    LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

                    BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                    S1.attrs.add("A");
                    S1.attrs.add("DDDD");

                    BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();
                    S2.attrs.add("BB");
                    S2.attrs.add("CCC");

                    BooleanFormulaParser.AttributeList S3 = new BooleanFormulaParser.AttributeList();
                    S3.attrs.add("A");
                    S3.attrs.add("BB");
                    S3.attrs.add("CCC");

                    G1 id1 = new G1();
                    Func.GetMCLG1RandomElement(id1);
                    ABE.RABE.MCL.SecretKey sk1 = new ABE.RABE.MCL.SecretKey();
                    scheme.KeyGen(sk1, BT, SP, mpk, msk, S1, id1);

                    G1 id2 = new G1();
                    Func.GetMCLG1RandomElement(id2);
                    ABE.RABE.MCL.SecretKey sk2 = new ABE.RABE.MCL.SecretKey();
                    scheme.KeyGen(sk2, BT, SP, mpk, msk, S2, id2);

                    ABE.RABE.MCL.SecretKey sk3 = new ABE.RABE.MCL.SecretKey();
                    scheme.KeyGen(sk3, BT, SP, mpk, msk, S3, id1);

                    scheme.Revoke(rl, id1, 10);
                    scheme.Revoke(rl, id2, 100);

                    ABE.RABE.MCL.PlainText m1 = new ABE.RABE.MCL.PlainText();
                    ABE.RABE.MCL.PlainText m2 = new ABE.RABE.MCL.PlainText();
                    ABE.RABE.MCL.PlainText m3 = new ABE.RABE.MCL.PlainText();
                    if(t == ABE.RABE.MCL.TYPE.XNM_2021) {
                        Func.GetMCLGTRandomElement(m1.m);
                    }
                    Func.GetMCLGTRandomElement(m2.m);
                    Func.GetMCLGTRandomElement(m3.m);
                    ABE.RABE.MCL.CipherText ct1 = new ABE.RABE.MCL.CipherText();
                    ABE.RABE.MCL.CipherText ct2 = new ABE.RABE.MCL.CipherText();

                    scheme.Encrypt(ct1, SP, mpk, MSP, m1, 5);
                    scheme.Encrypt(ct2, SP, mpk, MSP, m2, 50);

                    ABE.RABE.MCL.UpdateKey ku1 = new ABE.RABE.MCL.UpdateKey();
                    scheme.UpdateKeyGen(ku1, SP, mpk, BT, rl, 5);

                    ABE.RABE.MCL.UpdateKey ku2 = new ABE.RABE.MCL.UpdateKey();
                    scheme.UpdateKeyGen(ku2, SP, mpk, BT, rl, 50);

                    ABE.RABE.MCL.DecryptKey dk_1_1 = new ABE.RABE.MCL.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_1, SP, mpk, sk1, ku1, BT, rl);

                    ABE.RABE.MCL.DecryptKey dk_1_2 = new ABE.RABE.MCL.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_2, SP, mpk, sk1, ku2, BT, rl);

                    ABE.RABE.MCL.DecryptKey dk_2_1 = new ABE.RABE.MCL.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_1, SP, mpk, sk2, ku1, BT, rl);

                    ABE.RABE.MCL.DecryptKey dk_2_2 = new ABE.RABE.MCL.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_2, SP, mpk, sk2, ku2, BT, rl);

                    ABE.RABE.MCL.DecryptKey dk_3_1 = new ABE.RABE.MCL.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_1, SP, mpk, sk3, ku1, BT, rl);

                    ABE.RABE.MCL.DecryptKey dk_3_2 = new ABE.RABE.MCL.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_2, SP, mpk, sk3, ku2, BT, rl);

                    scheme.Decrypt(m3, SP, dk_1_1, MSP, ct1);
                    assertTrue(m3.isEqual(m1), "decrypt(dk_1_1, ct1) == m1");

                    scheme.Decrypt(m3, SP, dk_2_1, MSP, ct1);
                    assertFalse(m3.isEqual(m1), "policy false");

                    scheme.Decrypt(m3, SP, dk_3_1, MSP, ct1);
                    assertTrue(m3.isEqual(m1), "decrypt(dk_3_1, ct1) == m1");

                    scheme.Decrypt(m3, SP, dk_1_1, MSP, ct2);
                    assertFalse(m3.isEqual(m2), "different time");

                    assertThrows(NullPointerException.class, () -> {
                        scheme.Decrypt(m3, SP, dk_1_2, MSP, ct2);
                        assertFalse(m3.isEqual(m1), "decrypt(dk_1_2, ct1) != m1");
                    }, "id1 expired");
                }
            }

            @DisplayName("test MCL_swap impl")
            @ParameterizedTest(name = "test curve {0} with leaf node size = {1} RABE type = {2}")
            @MethodSource("ABETest#GetMCLSwapInvertNType")
            void MCLSwapTest(curve.MCL curve, int n, ABE.RABE.MCL_swap.TYPE t) {
                Func.MCLInit(curve);
                {
                    ABE.RABE.MCL_swap scheme = new ABE.RABE.MCL_swap();
                    ABE.RABE.MCL_swap.PublicParam SP = new ABE.RABE.MCL_swap.PublicParam(t);
                    ABE.RABE.MCL_swap.MasterPublicKey mpk = new ABE.RABE.MCL_swap.MasterPublicKey();
                    ABE.RABE.MCL_swap.MasterSecretKey msk = new ABE.RABE.MCL_swap.MasterSecretKey();
                    scheme.SetUp(mpk, msk);

                    base.BinaryTree.MCL_G2 BT = new base.BinaryTree.MCL_G2(n);
                    base.BinaryTree.MCL_G2.RevokeList rl = new base.BinaryTree.MCL_G2.RevokeList();

                    base.LSSS.MCL LSSS = new base.LSSS.MCL();
                    base.LSSS.MCL.Matrix MSP = new base.LSSS.MCL.Matrix();
                    BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                    LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

                    BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                    S1.attrs.add("A");
                    S1.attrs.add("DDDD");

                    BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();
                    S2.attrs.add("BB");
                    S2.attrs.add("CCC");

                    BooleanFormulaParser.AttributeList S3 = new BooleanFormulaParser.AttributeList();
                    S3.attrs.add("A");
                    S3.attrs.add("BB");
                    S3.attrs.add("CCC");

                    G2 id1 = new G2();
                    Func.GetMCLG2RandomElement(id1);
                    ABE.RABE.MCL_swap.SecretKey sk1 = new ABE.RABE.MCL_swap.SecretKey();
                    scheme.KeyGen(sk1, BT, SP, mpk, msk, S1, id1);

                    G2 id2 = new G2();
                    Func.GetMCLG2RandomElement(id2);
                    ABE.RABE.MCL_swap.SecretKey sk2 = new ABE.RABE.MCL_swap.SecretKey();
                    scheme.KeyGen(sk2, BT, SP, mpk, msk, S2, id2);

                    ABE.RABE.MCL_swap.SecretKey sk3 = new ABE.RABE.MCL_swap.SecretKey();
                    scheme.KeyGen(sk3, BT, SP, mpk, msk, S3, id1);

                    scheme.Revoke(rl, id1, 10);
                    scheme.Revoke(rl, id2, 100);

                    ABE.RABE.MCL_swap.PlainText m1 = new ABE.RABE.MCL_swap.PlainText();
                    ABE.RABE.MCL_swap.PlainText m2 = new ABE.RABE.MCL_swap.PlainText();
                    ABE.RABE.MCL_swap.PlainText m3 = new ABE.RABE.MCL_swap.PlainText();
                    Func.GetMCLGTRandomElement(m1.m);
                    Func.GetMCLGTRandomElement(m2.m);
                    Func.GetMCLGTRandomElement(m3.m);
                    ABE.RABE.MCL_swap.CipherText ct1 = new ABE.RABE.MCL_swap.CipherText();
                    ABE.RABE.MCL_swap.CipherText ct2 = new ABE.RABE.MCL_swap.CipherText();

                    scheme.Encrypt(ct1, SP, mpk, MSP, m1, 5);
                    scheme.Encrypt(ct2, SP, mpk, MSP, m2, 50);

                    ABE.RABE.MCL_swap.UpdateKey ku1 = new ABE.RABE.MCL_swap.UpdateKey();
                    scheme.UpdateKeyGen(ku1, SP, mpk, BT, rl, 5);

                    ABE.RABE.MCL_swap.UpdateKey ku2 = new ABE.RABE.MCL_swap.UpdateKey();
                    scheme.UpdateKeyGen(ku2, SP, mpk, BT, rl, 50);

                    ABE.RABE.MCL_swap.DecryptKey dk_1_1 = new ABE.RABE.MCL_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_1, SP, mpk, sk1, ku1, BT, rl);

                    ABE.RABE.MCL_swap.DecryptKey dk_1_2 = new ABE.RABE.MCL_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_2, SP, mpk, sk1, ku2, BT, rl);

                    ABE.RABE.MCL_swap.DecryptKey dk_2_1 = new ABE.RABE.MCL_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_1, SP, mpk, sk2, ku1, BT, rl);

                    ABE.RABE.MCL_swap.DecryptKey dk_2_2 = new ABE.RABE.MCL_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_2, SP, mpk, sk2, ku2, BT, rl);

                    ABE.RABE.MCL_swap.DecryptKey dk_3_1 = new ABE.RABE.MCL_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_1, SP, mpk, sk3, ku1, BT, rl);

                    ABE.RABE.MCL_swap.DecryptKey dk_3_2 = new ABE.RABE.MCL_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_2, SP, mpk, sk3, ku2, BT, rl);

                    scheme.Decrypt(m3, SP, dk_1_1, MSP, ct1);
                    assertTrue(m3.isEqual(m1), "decrypt(dk_1_1, ct1) == m1");

                    scheme.Decrypt(m3, SP, dk_2_1, MSP, ct1);
                    assertFalse(m3.isEqual(m1), "policy false");

                    scheme.Decrypt(m3, SP, dk_3_1, MSP, ct1);
                    assertTrue(m3.isEqual(m1), "decrypt(dk_3_1, ct1) == m1");

                    scheme.Decrypt(m3, SP, dk_1_1, MSP, ct2);
                    assertFalse(m3.isEqual(m2), "different time");

                    assertThrows(NullPointerException.class, () -> {
                        scheme.Decrypt(m3, SP, dk_1_2, MSP, ct2);
                        assertFalse(m3.isEqual(m1), "decrypt(dk_1_2, ct1) != m1");
                    }, "id1 expired");
                }
            }
        }
    }
}
