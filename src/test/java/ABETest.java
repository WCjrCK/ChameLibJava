import base.BinaryTree.PBC;
import it.unisa.dia.gas.jpbc.Element;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import utils.BooleanFormulaParser;

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

    public static Stream<Arguments> GetPBCInvertN() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a ->
                Stream.of(16, 32, 64).flatMap(b ->
                        Stream.of(Arguments.of(a, false, b), Arguments.of(a, true, b))
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
                scheme.SetUp(SP, mpk, msk);

                base.LSSS.PBC LSSS = new base.LSSS.PBC();
                base.LSSS.PBC.Matrix MSP = new base.LSSS.PBC.Matrix(SP.GP.Zr);
                BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

                BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();

                S1.attrs.add("A");
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
                ABE.MA_ABE.PBC.PublicParam GP = new ABE.MA_ABE.PBC.PublicParam();
                scheme.GlobalSetup(GP, curve);

                base.LSSS.PBC LSSS = new base.LSSS.PBC();
                base.LSSS.PBC.Matrix MSP = new base.LSSS.PBC.Matrix(GP.Zr);
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

                ABE.MA_ABE.PBC.PlainText m1 = new ABE.MA_ABE.PBC.PlainText(GP.GetGTElement());
                ABE.MA_ABE.PBC.PlainText m2 = new ABE.MA_ABE.PBC.PlainText(GP.GetGTElement());
                ABE.MA_ABE.PBC.PlainText m3 = new ABE.MA_ABE.PBC.PlainText(GP.GetGTElement());

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
            @ParameterizedTest(name = "test curve {0} swap_G1G2 {1} with leaf node size = {2}")
            @MethodSource("ABETest#GetPBCInvertN")
            void JPBCTest(curve.PBC curve, boolean swap_G1G2, int n) {
                ABE.RABE.PBC scheme = new ABE.RABE.PBC();
                ABE.RABE.PBC.PublicParam SP = new ABE.RABE.PBC.PublicParam(curve, swap_G1G2);
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

//                BT.PrintTheta();

                Element id2 = SP.GP.GetZrElement();
                ABE.RABE.PBC.SecretKey sk2 = new ABE.RABE.PBC.SecretKey();
                scheme.KeyGen(sk2, BT, SP, mpk, msk, S2, id2);

//                BT.PrintTheta();

                ABE.RABE.PBC.SecretKey sk3 = new ABE.RABE.PBC.SecretKey();
                scheme.KeyGen(sk3, BT, SP, mpk, msk, S3, id1);

                BT.PrintTheta();

                scheme.Revoke(rl, id1, 10);
                scheme.Revoke(rl, id2, 100);

                BT.GetUpdateKeyNode(rl, 50);
                BT.Print();

                ABE.RABE.PBC.PlainText m1 = new ABE.RABE.PBC.PlainText(SP.GP.GetGTElement());
                ABE.RABE.PBC.PlainText m2 = new ABE.RABE.PBC.PlainText(SP.GP.GetGTElement());
                ABE.RABE.PBC.PlainText m3 = new ABE.RABE.PBC.PlainText(SP.GP.GetGTElement());
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
        }
    }
}
