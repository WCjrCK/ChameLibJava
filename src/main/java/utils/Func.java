package utils;

import com.herumi.mcl.*;
import curve.Group;
import curve.MCL;
import curve.PBC;
import curve.params;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.util.Random;

@SuppressWarnings("rawtypes")
public class Func {
    public static void InitialLib() {
        System.loadLibrary("mcljava");
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
    }

    public static Field GetPBCField(Pairing pairing, Group group) {
        switch (group) {
            case G1: return pairing.getG1();
            case G2: return pairing.getG2();
            case GT: return pairing.getGT();
            default: throw new IllegalArgumentException("Unknown group");
        }
    }

    public static void MCLInit(MCL curve) {
        switch (curve) {
            case BN254:
                Mcl.SystemInit(Mcl.BN254);
                break;

            case BLS12_381:
                Mcl.SystemInit(Mcl.BLS12_381);
                break;

            case SECP256K1:
                Mcl.SystemInit(Mcl.SECP256K1);
                break;

            default: throw new IllegalArgumentException("Unknown group");
        }
    }

    public static Pairing PairingGen(PBC curve) {
        switch (curve) {
//            case A_80: return PairingFactory.getPairing(params.a_param_80);
//            case A_112: return PairingFactory.getPairing(params.a_param_112);
//            case A_128: return PairingFactory.getPairing(params.a_param_128);
//            case A_160: return PairingFactory.getPairing(params.a_param_160);
            case A: return PairingFactory.getPairing(params.a_param);

            case A1: return PairingFactory.getPairing(params.a1_param);

            case D_159: return PairingFactory.getPairing(params.d159_param);
            case D_201: return PairingFactory.getPairing(params.d201_param);
            case D_224: return PairingFactory.getPairing(params.d224_param);
            case D_105171_196_185: return PairingFactory.getPairing(params.d105171_196_185_param);
            case D_277699_175_167: return PairingFactory.getPairing(params.d277699_175_167_param);
            case D_278027_190_181: return PairingFactory.getPairing(params.d278027_190_181_param);

            case E: return PairingFactory.getPairing(params.e_param);

            case F: return PairingFactory.getPairing(params.f_param);
            case SM_9: return PairingFactory.getPairing(params.sm9_param);

            case G_149: return PairingFactory.getPairing(params.g149_param);

            default: throw new IllegalArgumentException("Unknown curve");
        }
    }

    public static BigInteger phi(BigInteger p, BigInteger q) {
        return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    public static BigInteger lcm(BigInteger a, BigInteger b) {
        return a.multiply(b).divide(a.gcd(b));
    }

    public static BigInteger getZq(Random rand, BigInteger q) {
        BigInteger res;
        do {
            res = new BigInteger(q.bitLength(), rand).mod(q);
        } while (res.compareTo(BigInteger.ZERO) <= 0 || res.compareTo(q) >= 0);
        return res;
    }

    public static G1 GetMCLG1RandomElement() {
        G1 res = new G1();
        byte[] m = new byte[128];
        Random random = new Random();
        do {
            random.nextBytes(m);
            Mcl.hashAndMapToG1(res, m);
        } while(res.isZero());
        return res;
    }

    public static G2 GetMCLG2RandomElement() {
        G2 res = new G2();
        byte[] m = new byte[128];
        Random random = new Random();
        do {
            random.nextBytes(m);
            Mcl.hashAndMapToG2(res, m);
        } while(res.isZero());
        return res;
    }

//    public static GT GetMCLGTRandomElement() {
//        GT res = new GT();
//        byte[] m = new byte[128];
//        Random random = new Random();
//        G1 g1 = new G1();
//        random.nextBytes(m);
//        Mcl.hashAndMapToG1(g1, m);
//        G2 g2 = new G2();
//        random.nextBytes(m);
//        Mcl.hashAndMapToG2(g2, m);
//        Mcl.pairing(res, g1, g2);
//        return res;
//    }

    public static Fr GetMCLZrRandomElement() {
        Fr res = new Fr();
        do {
            res.setByCSPRNG();
        } while(res.isZero());
        return res;
    }
}
