import com.herumi.mcl.*;
import curve.Group;
import curve.MCL;
import curve.PBC;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.junit.jupiter.api.*;
import utils.Func;
import utils.Hash;

import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

@SuppressWarnings({"rawtypes", "SuspiciousNameCombination"})
@Disabled
public class BadCaseTest {
    @BeforeEach
    public void init() {
        Func.InitialLib();
    }

    @DisplayName("PBC bad case")
    @Nested
    class JPBC_Bad_Case {
        @DisplayName("case 1")
        @Test
        void Case1() {
            InitialLib();
            curve.PBC curve = PBC.D_159;
            Group group = Group.GT;

            Pairing pairing = Func.PairingGen(curve);
            Field G = Func.GetPBCField(pairing, group);
            Element y = G.newRandomElement().getImmutable();
            Element L1 = G.newRandomElement().getImmutable();
            Element L2 = G.newRandomElement().getImmutable();
            System.out.printf("L1 = %s\n\nL2 = %s\n\n", L1, L2);
            System.out.printf("L1 == L2 ? %s\n\n", L1.isEqual(L2));
            Element H_y_L1 = Hash.H_PBC_2_1(G, y, L1);
            Element H_y_L2 = Hash.H_PBC_2_1(G, y, L2);
            System.out.printf("H(y, L1) = %s\n\n", H_y_L1);
            System.out.printf("H(y, L2) = %s\n\n", H_y_L2);
            System.out.printf("H(y, L1) == H(y, L2) ? %s\n\n", H_y_L1.isEqual(H_y_L2));
            assertFalse(H_y_L1.isEqual(H_y_L2));
        }

        @DisplayName("case 2")
        @Test
        void Case2() {
            InitialLib();
            curve.PBC curve = PBC.G_149;
            Group group = Group.G2;

            scheme.CH.FCR_CH_PreQA_DKS_2020.PBC scheme = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC();
            scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.PublicParam pp = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.PublicParam(curve, group);
            scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.PublicKey pk = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.PublicKey();
            scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.SecretKey sk = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.SecretKey();
            scheme.KeyGen(pk, sk, pp);
            Element m1 = pp.GP.GetZrElement();

            scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.HashValue H = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.HashValue();

            scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.Randomness R = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.Randomness();
            Element T1, T2;
            { // scheme.Hash
                Element xi, k_1_1, k_1_2;
                xi = pp.GP.GetZrElement();
                k_1_1 = pp.GP.GetZrElement();
                k_1_2 = pp.GP.GetZrElement();
                R.e_2 = pp.GP.GetZrElement();
                R.s_2 = pp.GP.GetZrElement();

                H.O = pp.g_1.powZn(m1).mul(pp.g_2.powZn(xi)).getImmutable();

                T1 = pp.g_1.powZn(k_1_1).mul(pp.g_2.powZn(k_1_2));
                R.e_1 = pp.H(
                        pk.y, H.O, m1,
                        T1,
                        pp.g_1.powZn(R.s_2).div(pk.y.powZn(R.e_2))
                ).sub(R.e_2);
                R.s_1_1 = k_1_1.add(R.e_1.mul(m1));
                R.s_1_2 = k_1_2.add(R.e_1.mul(xi));
            }
            T2 = pp.g_1.powZn(R.s_1_1).mul(pp.g_2.powZn(R.s_1_2)).div(H.O.powZn(R.e_1));
            System.out.printf("T1 = %s\n\nT2 = %s\n\n", T1, T2);
            System.out.printf("str(T1) == str(T2) ? %s\n\n", T1.toString().equals(T2.toString()));
            System.out.printf("T1 == T2 ? %s\n\n", T1.isEqual(T2));

//            assertFalse((T1.isEqual(T2) ^ T1.toString().equals(T2.toString())));

            Element m2 = pp.GP.GetZrElement();
            assertFalse(m1.isEqual(m2), "m1 != m2");

            scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.HashValue h1 = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.HashValue();
            scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.Randomness r1 = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.Randomness();
            scheme.Hash(h1, r1, pp, pk, m1);
            assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
            assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
        }

        @DisplayName("case 3")
        @Test
        void Case3() {
            // only pbc make fatal error
             PairingFactory.getInstance().setUsePBCWhenPossible(true);

            // jpbc is ok
//            PairingFactory.getInstance().setUsePBCWhenPossible(false);

            curve.PBC curve = PBC.G_149;
            Group group = Group.GT;

            scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.PublicParam pp = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.PublicParam(curve, group);
            {
                Pairing pairing = Func.PairingGen(curve);
                pp.GP.G = Func.GetPBCField(pairing, group);
                pp.g_1 = pp.GP.GetGElement();
                byte[] hash = Hash.HASH(pp.g_1.toString());
                System.out.println(Arrays.toString(hash));
                pp.GP.G.newElementFromHash(hash, 0, hash.length).getImmutable();
            }
        }
    }

    @DisplayName("MCL bad case")
    @Nested
    class MCL_Bad_Case {
        @DisplayName("case 1")
        @Test
        void Case1() {
            Func.MCLInit(MCL.SECP256K1);
            G2 res = new G2();
            byte[] m = new byte[128];
            Random random = new Random();
            random.nextBytes(m);
            Mcl.hashAndMapToG2(res, m);
        }

        @DisplayName("case 2")
        @Test
        void Case2() {
            Func.MCLInit(MCL.SECP256K1);
            G1 res = new G1();
            byte[] m = {57, 12, -90, 111, 104, 83, 112, 32, -115, 53, 52, 4, -52, 37, 104, -49, 87, 1, -87, 118, -27, 121, 119, -36, 117, 83, 49, -76, -21, 76, -21, 21, -61, 13, 25, 114, 86, -118, -123, 34, 67, -118, 109, -53, 75, 2, -74, -37, 77, -123, 51, -127, -81, 92, 115, -6, 125, -40, 85, -114, 45, -18, -15, -64, 111, -120, 105, 24, 119, -4, -114, -18, -108, -54, 12, -6, 126, -127, -10, 62, -98, -99, 102, 39, -122, 105, -100, 91, 88, -90, -100, 46, 53, -82, -97, -103, -29, 11, -41, 120, 15, 33, 27, 70, -81, 89, 92, 126, -1, 65, -83, 65, -86, -54, -96, 7, -32, -78, 108, -70, -127, 32, 40, -101, 30, -57, -22, -113};

            System.out.println(Arrays.toString(m));
            System.out.println(m.length);
            Mcl.hashAndMapToG1(res, m);
            System.out.println(res);
            Fp x_ = new Fp();
            Fp y_ = new Fp();
            x_.setStr("9336347108682737102384939936052420093564155833550610091224922170113216011716");
            y_.setStr("35406110276716635486051858434924396922230345568064703334853336408913686925305");
            res.set(x_, y_);

            System.out.println(res);
            Fr x = new Fr();
            Fr y = new Fr();
            x.setStr("54213485713551791915459610488006789559600204897879063708647939023076932717721");
            y.setStr("50411627248006713229948837792376515231153749021572962616274577535371903673399");
            G1 tmp1 = new G1();
            G1 tmp2 = new G1();

            // tmp1 = (res ^ x) ^ y
            Mcl.mul(tmp1, res, x);
            Mcl.mul(tmp1, tmp1, y);

            Mcl.mul(x, x, y);
            // tmp2 = res ^ (x * y)
            Mcl.mul(tmp2, res, x);
            System.out.println(tmp1);
            System.out.println(tmp2);
            System.out.println(x);
            System.out.println(y);
            assertTrue(tmp1.equals(tmp2), "tmp1 != tmp2");


//[-109, 105, -69, 119, -12, -20, 17, -111, 2, 39, -125, -58, -125, 56, -56, -63, 94, 29, 107, -119, -98, -50, -22, 34, 121, 29, 100, -19, -10, -80, -73, 74, -13, -4, 39, 87, 24, -82, 35, 30, -92, -2, 76, 121, -80, -94, -103, -38, -83, 4, -84, -54, -6, 6, 37, 11, 56, 108, -5, -25, 88, 41, 120, -49, 115, 19, 5, -39, 95, 50, -80, -33, 76, 68, -122, 99, -24, 91, -81, 51, -12, -94, 14, 94, -39, -13, -17, -93, 59, -35, -4, 113, -57, -92, -72, -126, 52, 64, -104, 34, -91, 97, -48, 50, -49, -101, 99, -3, 22, 7, -53, -97, 72, -120, 92, -98, 31, -100, -16, -77, -101, 71, 97, 33, 73, -27, -87, -90]
//            1 94387655941979127875547269027669106101925150018491204252905962606829219904373 113665453905897929784330060415929079250036392089956575252971182845793779315153
//            106710729501573572990993223013947373090540085456861206151552
//            878527845313324791924604320371259314084299492068183947533245034037542682
//
//
//            12312415124
//                    [61, 43, 119, -126, -14, 12, -16, 45, -72, -19, 83, 98, -65, -46, -32, -30, 1, 127, 12, 35, -43, -22, -116, 45, 0, -52, 92, -8, -95, -70, -94, 24, 94, -3, 68, 13, -22, 75, 8, -15, -85, -67, -24, -116, 72, 18, 21, -115, -74, -96, -4, -110, 21, -91, -26, -4, -85, -66, 42, -26, 90, 79, 48, 84, -10, -71, 65, -109, 119, 70, -88, -42, -6, -60, -12, -68, -87, -7, -127, -51, 28, 101, 115, -51, -105, -113, 31, -89, -71, -78, 66, -122, -125, 28, 18, -69, -7, 65, 52, 22, -34, -78, 121, 36, -100, -58, 127, -65, 73, -7, 29, 114, 56, 117, -55, -53, 72, -68, 75, -31, -124, 46, 8, -111, 62, -49, 50, -35]
//            1 6227909552207948271261996018121000745981419634714267083155004792727646459171 18605579314144549779224094453360024400781689761095909054174670822924174956225
//            4365080219115695403723430478736869835164089722546009873723136283336350075020
//            73203181676386944745011571727393821359252884620538104062543514628638849162594
//            target:
//            1 104865760140316453839872134785771191876157230828034990653306976681214396076331 33323162562177257379543941596376494265549399845549427319195169679500699069232
//            90398126388094833862249214474623746569750088723120193847693770252655773577570
//            L: 1 43338938749512580003895839241970357249567518298218063058925109061375674594970 27106953170681098297869398996511766228539615180151655276779997727422835742080
//            t: 1 6227909552207948271261996018121000745981419634714267083155004792727646459171 18605579314144549779224094453360024400781689761095909054174670822924174956225
//            R: 1 46564818529864337577905703618681417643930588273017954825430869768529283184455 107563817904155266948089250310738437068049923697834415317624313328162315442994
//            R: 1 93710496771438937937446068371226578125685684476225881991351899954157735026830 107923176960848041238438668636331897903667543915631621746871913334711522306635
//
//                    [-22, -100, -106, 102, -53, 125, 30, 10, -121, 11, -84, 106, -80, 91, -108, -114, -99, -112, -110, 23, 118, 62, -58, -106, 88, -33, 103, 51, 126, 14, -43, 23, 68, 26, -123, -18, -93, 19, 60, -84, 118, 82, -49, 36, -77, -1, 117, 40, -33, 79, -49, 64, 90, -11, 2, 29, 115, -11, -63, -123, 21, -83, -14, 110, -3, -73, 22, -82, -39, -56, -86, 120, -24, -4, 46, -111, -106, 8, 16, 115, 59, 94, 43, 116, -56, -76, -27, -36, -104, -45, -64, 93, -91, 9, 102, 80, 9, 44, -100, 69, -79, 4, 34, 103, -43, 42, -83, -59, -64, 127, -32, 44, -76, -119, 49, -12, -82, 79, 26, -33, 34, 45, -53, 78, 77, -6, -31, -30]
//            1 30709384950259553530320853748870005785974464043929640219066326857851805605580 108282189375917746187464435892390655285706081044146979806978536934739516919571
//            62618564377086408931023396825534992471580413455943073563203042641138155305142
//            68625553125099846070165612427889885074257138722279199982652272807339295471033
//            target:
//            1 104865760140316453839872134785771191876157230828034990653306976681214396076331 33323162562177257379543941596376494265549399845549427319195169679500699069232
//            43914017831837722387104996954077435247902320332969725184859133892662651714864
//            L: 1 82576718260936201500370904418313657645995144357139334943031125347647199150061 5845803421177504031010238221452434539740752350846397314717761430521618451957
//            t: 1 30709384950259553530320853748870005785974464043929640219066326857851805605580 108282189375917746187464435892390655285706081044146979806978536934739516919571
//            R: 1 17064722013263523339789710353140124673568509446848041009554614144239996638784 103730554913528912254554467936873828631870775090150664686207727246302126512471
//            R: 1 18731893286753986162429951294640093142471697366247718996008015423279555952514 21343641601893507458433947764146696736639473670675711284408094397547516558310
//
//            UForge
//            L: 1 43338938749512580003895839241970357249567518298218063058925109061375674594970 27106953170681098297869398996511766228539615180151655276779997727422835742080
//            R: 1 93710496771438937937446068371226578125685684476225881991351899954157735026830 107923176960848041238438668636331897903667543915631621746871913334711522306635
//            t: 1 6227909552207948271261996018121000745981419634714267083155004792727646459171 18605579314144549779224094453360024400781689761095909054174670822924174956225
//            1 94387655941979127875547269027669106101925150018491204252905962606829219904373 113665453905897929784330060415929079250036392089956575252971182845793779315153
//            38890552292238894104376347848664894112651769930684582362444025943942901668930
//            90398126388094833862249214474623746569750088723120193847693770252655773577570
//            81534795900874475908393522590075281195085462248669900636828546412098014863499
//            1 104865760140316453839872134785771191876157230828034990653306976681214396076331 33323162562177257379543941596376494265549399845549427319195169679500699069232
//            1 43338938749512580003895839241970357249567518298218063058925109061375674594970 27106953170681098297869398996511766228539615180151655276779997727422835742080
//            1 93104071334904364684437929640087609605391302694683645436110588881252793791424 75173009619794430823854644922495230563510482021668445270601217461663116681905
        }
    }
}
