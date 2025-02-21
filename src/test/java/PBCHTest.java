import curve.PBC;
import it.unisa.dia.gas.jpbc.Element;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import utils.BooleanFormulaParser;
import utils.Func;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

public class PBCHTest {
    @BeforeAll
    static void initTest() {
        InitialLib();
    }

    @DisplayName("test LSSS PBC impl")
    @Test
    void LSSSPBCTest() {
        base.LSSS.PBC lsss_gen =  new base.LSSS.PBC();
        base.LSSS.PBC.Matrix mat =  new base.LSSS.PBC.Matrix(Func.PairingGen(PBC.A).getZr());
        BooleanFormulaParser.PolicyList pi =  new BooleanFormulaParser.PolicyList();
//        lsss_gen.GenLSSSMatrices(mat, pi, "P555&(((P1&P2)|(P3&P4))|((P1|P2)&(P3|P4)))");
//        lsss_gen.GenLSSSMatrices(mat, pi, "P555");
//        lsss_gen.GenLSSSMatrices(mat, pi, "A&(DDDD|(BB&CCC))");
        lsss_gen.GenLSSSMatrices(mat, pi, "A&(D|(B&C))");
//        lsss_gen.GenLSSSMatrices(mat, pi, "A&D&B&C");
        mat.Print();
        pi.Print();
        BooleanFormulaParser.AttributeList S = new BooleanFormulaParser.AttributeList();
        S.attrs.add("A");
        S.attrs.add("B");
        S.attrs.add("C");
        S.attrs.add("D");
        S.Print();
        base.LSSS.PBC.Matrix.Vector omega = new base.LSSS.PBC.Matrix.Vector();
        mat.Solve(omega, S);
        omega.Print();

        Element x = mat.G.newElementFromBytes("123".getBytes(StandardCharsets.UTF_8));
        System.out.println(Arrays.toString(x.toBytes()));
        System.out.println(Arrays.toString(x.toCanonicalRepresentation()));
        System.out.println(Arrays.toString("123".getBytes(StandardCharsets.UTF_8)));
    }


    @DisplayName("test paper 《Fine-Grained and Controlled Rewriting in Blockchains Chameleon-Hashing Gone Attribute-Based》")
    @Nested
    class FineGrainedAndControlledRewritingInBlockchainsChameleonHashingGoneAttributeBasedTest {
        @DisplayName("test PBC impl")
        @ParameterizedTest(name = "test curve {0} swap_G1G2 {1}")
        @MethodSource("ABETest#GetPBCInvert")
        void JPBCTest(curve.PBC curve, boolean swap_G1G2) {
            Random rand = new Random();
            scheme.PBCH.PCH_DSS_2019.PBC scheme = new scheme.PBCH.PCH_DSS_2019.PBC(128);
            scheme.PBCH.PCH_DSS_2019.PBC.PublicParam pk_PCH = new scheme.PBCH.PCH_DSS_2019.PBC.PublicParam();
            scheme.PBCH.PCH_DSS_2019.PBC.MasterSecretKey sk_PCH = new scheme.PBCH.PCH_DSS_2019.PBC.MasterSecretKey();
            scheme.SetUp(pk_PCH, sk_PCH, curve, swap_G1G2);

            base.LSSS.PBC LSSS = new base.LSSS.PBC();
            base.LSSS.PBC.Matrix MSP = new base.LSSS.PBC.Matrix(pk_PCH.mpk_ABE.Zr);
            BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
            LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

            BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
            BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();

            S1.attrs.add("A");
            S1.attrs.add("DDDD");

            S2.attrs.add("BB");
            S2.attrs.add("CCC");

            scheme.PBCH.PCH_DSS_2019.PBC.SecretKey sk1 = new scheme.PBCH.PCH_DSS_2019.PBC.SecretKey();
            scheme.PBCH.PCH_DSS_2019.PBC.SecretKey sk2 = new scheme.PBCH.PCH_DSS_2019.PBC.SecretKey();
            scheme.KeyGen(sk1, pk_PCH, sk_PCH, S1);
            scheme.KeyGen(sk2, pk_PCH, sk_PCH, S2);

            BigInteger m1 = new BigInteger(512, rand);
            BigInteger m2 = new BigInteger(512, rand);

            scheme.PBCH.PCH_DSS_2019.PBC.HashValue h1 = new scheme.PBCH.PCH_DSS_2019.PBC.HashValue();
            scheme.PBCH.PCH_DSS_2019.PBC.HashValue h2 = new scheme.PBCH.PCH_DSS_2019.PBC.HashValue();
            scheme.PBCH.PCH_DSS_2019.PBC.Randomness r1 = new scheme.PBCH.PCH_DSS_2019.PBC.Randomness();
            scheme.PBCH.PCH_DSS_2019.PBC.Randomness r2 = new scheme.PBCH.PCH_DSS_2019.PBC.Randomness();
            scheme.PBCH.PCH_DSS_2019.PBC.Randomness r1_p = new scheme.PBCH.PCH_DSS_2019.PBC.Randomness();

            scheme.Hash(h1, r1, pk_PCH, MSP, m1);
            scheme.Hash(h2, r2, pk_PCH, MSP, m2);
            assertTrue(scheme.Check(h1, r1, pk_PCH, m1), "H(m1) valid");
            assertFalse(scheme.Check(h1, r1, pk_PCH, m2), "H(m2) invalid");

            scheme.Adapt(r1_p, h1, r1, pk_PCH, MSP, sk1, m1, m2);
            assertTrue(scheme.Check(h1, r1_p, pk_PCH, m2), "Adapt(m2) valid");
            assertFalse(scheme.Check(h1, r1_p, pk_PCH, m1), "Adapt(m1) invalid");
        }
    }
}
