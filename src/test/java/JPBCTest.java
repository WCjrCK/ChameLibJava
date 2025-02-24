import curve.params;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.e.TypeECurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.f.TypeFCurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pbc.curve.PBCTypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pbc.curve.PBCTypeDCurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pbc.curve.PBCTypeGCurveGenerator;
import org.junit.jupiter.api.*;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

@DisplayName("jPBC base test")
public class JPBCTest {
    @BeforeEach
    void initTest() {
        assertTrue(PairingFactory.getInstance().isPBCAvailable(),
                "need config lib: http://gas.dia.unisa.it/projects/jpbc/docs/pbcwrapper.html");
        InitialLib();
    }

    void baseRun(Pairing pairing) {
        // 获取群G1, G2, GT
        var G1 = pairing.getG1();
        var G2 = pairing.getG2();

        // 随机选择主私钥
        BigInteger N = G1.getOrder();
        BigInteger ks = new BigInteger(N.bitLength(), new SecureRandom()).mod(N);
        BigInteger ke = new BigInteger(N.bitLength(), new SecureRandom()).mod(N);

        // 获取生成元
        Element P1 = G1.newRandomElement().getImmutable();
        Element P2 = G2.newRandomElement().getImmutable();

        // 计算主私钥
        Element P2_p = P2.mul(ks).getImmutable();
        Element P1_p = P1.mul(ke).getImmutable();

        // 计算pairing
        Element GT_1 = pairing.pairing(P1, P2);
        Element GT_2 = pairing.pairing(P1_p, P2_p);
        assertTrue(GT_1.pow(ks.multiply(ke)).isEqual(GT_2), "G1 power not equal G2!");
    }

    @DisplayName("test curve type a")
    @Nested
    class TypeATests {
        @DisplayName("test random curve")
        @Test
        void randomCurveTest() {
            //使用自定义曲线
            PBCTypeACurveGenerator pg = new PBCTypeACurveGenerator(160, 512);
            baseRun(PairingFactory.getPairing(pg.generate()));
        }

        @DisplayName("test curve a")
        @Test
        void aTest() {
            baseRun(PairingFactory.getPairing(params.a_param));
        }

//        @DisplayName("test curve a_80")
//        @Test
//        void a_80Test() {
//            baseRun(PairingFactory.getPairing(params.a_param_80));
//        }
//
//        @DisplayName("test curve a_112")
//        @Test
//        void a_112Test() {
//            baseRun(PairingFactory.getPairing(params.a_param_112));
//        }
//
//        @DisplayName("test curve a_128")
//        @Test
//        void a_128Test() {
//            baseRun(PairingFactory.getPairing(params.a_param_128));
//        }
//
//        @DisplayName("test curve a_160")
//        @Test
//        void a_160Test() {
//            baseRun(PairingFactory.getPairing(params.a_param_160));
//        }
    }

    @DisplayName("test curve type a1")
    @Nested
    class TypeA1Tests {
        @DisplayName("test random curve")
        @Test
        void randomCurveTest() {
            //使用自定义曲线，参数大了生成很慢
            TypeA1CurveGenerator pg = new TypeA1CurveGenerator(3, 517);
            baseRun(PairingFactory.getPairing(pg.generate()));
        }

        @DisplayName("test curve a1")
        @Test
        void a1Test() {
            baseRun(PairingFactory.getPairing(params.a1_param));
        }
    }

    @DisplayName("test curve type d")
    @Nested
    class TypeDTests {
        @DisplayName("test random curve")
        @Test
        void randomCurveTest() {
            //使用自定义曲线
            PBCTypeDCurveGenerator pg = new PBCTypeDCurveGenerator(9563);
            baseRun(PairingFactory.getPairing(pg.generate()));
        }

        @DisplayName("test curve d159")
        @Test
        void d159Test() {
            baseRun(PairingFactory.getPairing(params.d159_param));
        }

        @DisplayName("test curve d201")
        @Test
        void d201Test() {
            baseRun(PairingFactory.getPairing(params.d201_param));
        }

        @DisplayName("test curve d224")
        @Test
        void d224Test() {
            baseRun(PairingFactory.getPairing(params.d224_param));
        }

        @DisplayName("test curve d105171_196_185")
        @Test
        void d105171_196_185Test() {
            baseRun(PairingFactory.getPairing(params.d105171_196_185_param));
        }

        @DisplayName("test curve d277699_175_167")
        @Test
        void d277699_175_167Test() {
            baseRun(PairingFactory.getPairing(params.d277699_175_167_param));
        }

        @DisplayName("test curve d278027_190_181")
        @Test
        void d278027_190_181Test() {
            baseRun(PairingFactory.getPairing(params.d278027_190_181_param));
        }
    }

    @DisplayName("test curve type e")
    @Nested
    class TypeETests {
        @DisplayName("test random curve")
        @Test
        void randomCurveTest() {
            //使用自定义曲线，参数大了生成很慢
            TypeECurveGenerator pg = new TypeECurveGenerator(160, 1024);
            baseRun(PairingFactory.getPairing(pg.generate()));
        }

        @DisplayName("test curve e")
        @Test
        void eTest() {
            baseRun(PairingFactory.getPairing(params.e_param));
        }
    }

    @DisplayName("test curve type f")
    @Nested
    class TypeFTests {
        @DisplayName("test random curve")
        @Test
        void randomCurveTest() {
            //使用自定义曲线，参数大了生成很慢
            TypeFCurveGenerator pg = new TypeFCurveGenerator(160);
            baseRun(PairingFactory.getPairing(pg.generate()));
        }

        @DisplayName("test curve f")
        @Test
        void fTest() {
            baseRun(PairingFactory.getPairing(params.f_param));
        }

        @DisplayName("test curve sm9")
        @Test
        void sm9Test() {
            baseRun(PairingFactory.getPairing(params.sm9_param));
        }
    }

    @DisplayName("test curve type g")
    @Nested
    class TypeGTests {
        @DisplayName("test random curve")
        @Test
        void randomCurveTest() {
            //使用自定义曲线，参数大了生成很慢
            PBCTypeGCurveGenerator pg = new PBCTypeGCurveGenerator(35707);
            baseRun(PairingFactory.getPairing(pg.generate()));
        }

        @DisplayName("test curve g149")
        @Test
        void g149Test() {
            baseRun(PairingFactory.getPairing(params.g149_param));
        }
    }
}
