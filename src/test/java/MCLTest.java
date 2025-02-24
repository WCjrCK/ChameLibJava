import org.junit.jupiter.api.*;
import com.herumi.mcl.*;

import static org.junit.jupiter.api.Assertions.*;
import static utils.Func.InitialLib;

@SuppressWarnings("SuspiciousNameCombination")
@DisplayName("MCL base test")
@Disabled // for parallel mode
public class MCLTest {
    @BeforeEach
    void initTest() {
        InitialLib();
    }

    public static void BLSsignature(G2 Q) {
        Fr s = new Fr();
        s.setByCSPRNG(); // secret key
        G2 pub = new G2();
        Mcl.mul(pub, Q, s); // public key = sQ

        byte[] m = "signature test".getBytes();
        G1 H = new G1();
        Mcl.hashAndMapToG1(H, m); // H = Hash.java(m)
        G1 sign = new G1();
        Mcl.mul(sign, H, s); // signature of m = s H

        GT e1 = new GT();
        GT e2 = new GT();
        Mcl.pairing(e1, H, pub); // e1 = e(H, s Q)
        Mcl.pairing(e2, sign, Q); // e2 = e(s H, Q);
        assertTrue(e1.equals(e2),"verify signature");
    }

    public static void testCurve(int curveType) {
        Mcl.SystemInit(curveType);
        Fr x = new Fr(5);
        Fr y = new Fr(-2);
        Fr z = new Fr(5);
        assertFalse(x.equals(y), "x != y");
        assertTrue(x.equals(z), "x == z");
        assertEquals("5", x.toString(), "x == 5");
        Mcl.add(x, x, y);
        assertEquals("3", x.toString(), "x == 3");
        Mcl.mul(x, x, x);
        assertEquals("9", x.toString(), "x == 9");
        assertEquals((new Fr("12")).toString(), "12", "x == 12");
        assertEquals((new Fr("12", 16)).toString(), "18", "x == 18");
        assertEquals((new Fr("255")).toString(16), "ff", "x == ff");
        Mcl.inv(y, x);
        Mcl.mul(x, y, x);
        assertTrue(x.isOne(), "x == 1");
        {
            byte[] b = x.serialize();
            Fr t = new Fr();
            t.deserialize(b);
            assertTrue(x.equals(t), "serialize");
            t.setLittleEndianMod(b);
            assertTrue(x.equals(t), "setLittleEndianMod");
            t.setHashOf(b);
            assertFalse(x.equals(t), "setHashOf");
            Fr u = new Fr();
            u.setHashOf(new byte[]{1,2,3});
            assertFalse(u.equals(t), "setHashOf - different");
        }
        G1 P = new G1();
        Mcl.hashAndMapToG1(P, "test".getBytes());
        byte[] buf = { 1, 2, 3, 4 };
        Mcl.hashAndMapToG1(P, buf);
        Mcl.neg(P, P);
        {
            byte[] b = P.serialize();
            G1 t = new G1();
            t.deserialize(b);
            assertTrue(P.equals(t), "serialize");
        }

        G2 Q = new G2();
        Mcl.hashAndMapToG2(Q, "abc".getBytes());

        Mcl.hashAndMapToG1(P, "This is a pen".getBytes());
        {
            String s = P.toString();
            G1 P1 = new G1();
            P1.setStr(s);
            assertTrue(P1.equals(P), "P == P1");
        }
        {
            byte[] b = Q.serialize();
            G2 t = new G2();
            t.deserialize(b);
            assertTrue(Q.equals(t), "serialize");
        }

        GT e = new GT();
        Mcl.pairing(e, P, Q);
        GT e1 = new GT();
        GT e2 = new GT();
        Fr c = new Fr("1234567890123234928348230428394234");
        G2 cQ = new G2(Q);
        Mcl.mul(cQ, Q, c); // cQ = Q * c
        Mcl.pairing(e1, P, cQ);
        Mcl.pow(e2, e, c); // e2 = e^c
        assertTrue(e1.equals(e2), "e1 == e2");
        {
            byte[] b = e1.serialize();
            GT t = new GT();
            t.deserialize(b);
            assertTrue(e1.equals(t), "serialize");
        }
        G1 cP = new G1(P);
        Mcl.mul(cP, P, c); // cP = P * c
        Mcl.pairing(e1, cP, Q);
        assertTrue(e1.equals(e2), "e1 == e2");
        Mcl.inv(e1, e1);
        Mcl.mul(e1, e1, e2);
        e2.setStr("1 0 0 0 0 0 0 0 0 0 0 0");
        assertTrue(e1.equals(e2), "e1 == 1");
        assertTrue(e1.isOne(), "e1 == 1");

        BLSsignature(Q);
    }

    public static void testG1Curve(int curveType) {
        Mcl.SystemInit(curveType);
        Fp x = new Fp(123);
        G1 P = new G1();
        P.tryAndIncMapTo(x);
        P.normalize();
    }

    @DisplayName("test BN254")
    @Test
    void BN254Test() {
        testCurve(Mcl.BN254);
    }

    @DisplayName("test BLS12_381")
    @Test
    void BLS12_381Test() {
        testCurve(Mcl.BLS12_381);
    }

    @DisplayName("test SECP256K1")
    @Test
    void SECP256K1Test() {
        testG1Curve(Mcl.SECP256K1);
    }
}
