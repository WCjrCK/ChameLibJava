import curve.Group;
import curve.PBC;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.junit.jupiter.api.*;
import utils.Func;
import utils.Hash;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static utils.Func.InitialLib;

@SuppressWarnings("rawtypes")
@Disabled
public class BadCaseTest {
    @DisplayName("PBC bad case 1")
    @Test
    void JPBCBadCase1() {
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

    @DisplayName("PBC bad case 2")
    @Test
    void JPBCBadCase2() {
        InitialLib();
        curve.PBC curve = PBC.D_159;
        Group group = Group.G2;

        scheme.CH.FCR_CH_PreQA_DKS_2020.PBC scheme = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC();
        scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.PublicParam pp = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.PublicParam();
        scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.PublicKey pk = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.PublicKey();
        scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.SecretKey sk = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.SecretKey();
        scheme.SetUp(pp, curve, group);
        scheme.KeyGen(pk, sk, pp);
        Element m1 = pp.GetZrElement();

        scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.HashValue H = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.HashValue();

        scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.Randomness R = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.Randomness();
        Element T1, T2;
        { // scheme.Hash
            Element xi, k_1_1, k_1_2;
            xi = pp.GetZrElement();
            k_1_1 = pp.GetZrElement();
            k_1_2 = pp.GetZrElement();
            R.e_2 = pp.GetZrElement();
            R.s_2 = pp.GetZrElement();

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

        assertFalse(T1.isEqual(T2));
    }
    @DisplayName("PBC bad case 3")
    @Test
    void JPBCBadCase3() {
        // only pbc make fatal error
        // PairingFactory.getInstance().setUsePBCWhenPossible(true);

        // jpbc is ok
        PairingFactory.getInstance().setUsePBCWhenPossible(false);

        curve.PBC curve = PBC.G_149;
        Group group = Group.GT;

        scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.PublicParam pp = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.PublicParam();
        {
            Pairing pairing = Func.PairingGen(curve);
            pp.G = Func.GetPBCField(pairing, group);
            pp.g_1 = pp.GetGElement();
            byte[] hash = Hash.HASH(pp.g_1.toString());
            System.out.println(Arrays.toString(hash));
            pp.G.newElementFromHash(hash, 0, hash.length).getImmutable();
        }
    }
}
