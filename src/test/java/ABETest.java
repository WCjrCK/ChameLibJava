import org.junit.jupiter.api.BeforeAll;
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

    @BeforeAll
    static void initTest() {
        InitialLib();
    }

    @DisplayName("test paper 《FAME: Fast Attribute-based Message Encryption》")
    @Nested
    class FAMEFastAttributeBasedMessageEncryptionTest {
        @DisplayName("test PBC impl")
        @ParameterizedTest(name = "test curve {0} swap_G1G2 {1}")
        @MethodSource("ABETest#GetPBCInvert")
        void JPBCTest(curve.PBC curve, boolean swap_G1G2) {
            ABE.FAME.PBC scheme = new ABE.FAME.PBC();
            ABE.FAME.PBC.PublicParam SP = new ABE.FAME.PBC.PublicParam();
            ABE.FAME.PBC.MasterSecretKey msk = new ABE.FAME.PBC.MasterSecretKey();
            scheme.SetUp(SP, msk, curve, swap_G1G2);

            base.LSSS.PBC LSSS = new base.LSSS.PBC();
            base.LSSS.PBC.Matrix MSP = new base.LSSS.PBC.Matrix(SP.Zr);
            BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
            LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

            BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
            BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();

            S1.attrs.add("A");
            S1.attrs.add("DDDD");

            S2.attrs.add("BB");
            S2.attrs.add("CCC");

            ABE.FAME.PBC.SecretKey sk1 = new ABE.FAME.PBC.SecretKey();
            scheme.KeyGen(sk1, msk, SP, S1);
            ABE.FAME.PBC.SecretKey sk2 = new ABE.FAME.PBC.SecretKey();
            scheme.KeyGen(sk2, msk, SP, S2);

            ABE.FAME.PBC.PlainText m1 = new ABE.FAME.PBC.PlainText(SP.GetGTElement());
            ABE.FAME.PBC.PlainText m2 = new ABE.FAME.PBC.PlainText(SP.GetGTElement());
            ABE.FAME.PBC.PlainText m3 = new ABE.FAME.PBC.PlainText(SP.GetGTElement());
            ABE.FAME.PBC.CipherText ct1 = new ABE.FAME.PBC.CipherText();
            ABE.FAME.PBC.CipherText ct2 = new ABE.FAME.PBC.CipherText();

            scheme.Encrypt(ct1, SP, MSP, m1);
            scheme.Encrypt(ct2, SP, MSP, m2);

            scheme.Decrypt(m3, SP, MSP, ct1, sk1);
            assertTrue(m3.isEqual(m1), "decrypt(sk1, ct1) != m1");

            scheme.Decrypt(m3, SP, MSP, ct2, sk1);
            assertTrue(m3.isEqual(m2), "decrypt(sk1, ct2) != m2");

            scheme.Decrypt(m3, SP, MSP, ct1, sk2);
            assertFalse(m3.isEqual(m1), "decrypt(sk2, ct1) invalid");
            assertFalse(m3.isEqual(m2), "decrypt(sk2, ct1) invalid");
        }
    }
}
