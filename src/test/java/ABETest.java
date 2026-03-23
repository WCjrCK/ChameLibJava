import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import utils.BooleanFormulaParser;

import java.util.EnumSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
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

    @BeforeEach
    void initTest() {
        InitialLib();
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
}
