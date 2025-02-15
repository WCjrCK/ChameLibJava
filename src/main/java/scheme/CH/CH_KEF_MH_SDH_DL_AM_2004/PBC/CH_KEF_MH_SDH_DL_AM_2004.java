package scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC;

/*
 * On the Key Exposure Problem in Chameleon Hashes
 * P12. Scheme based on SDH and DL
 */

import curve.PBC;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;
import utils.Hash;

import java.math.BigInteger;
import java.util.Random;

@SuppressWarnings("rawtypes")
public class CH_KEF_MH_SDH_DL_AM_2004 {
    Random rand = new Random();
    Pairing pairing;
    Field G;

    public CH_KEF_MH_SDH_DL_AM_2004(PBC curve) {
        pairing = Func.PairingGen(curve);
        G = pairing.getG1();
    }

    public void KeyGen(PublicKey pk, SecretKey sk) {
        sk.x = Func.getZq(rand, G.getOrder());
        pk.g = G.newRandomElement().getImmutable();
        pk.h = pk.g.pow(sk.x).getImmutable();
    }

    public void Hash(HashValue h, Randomness r, PublicKey pk, BigInteger L, BigInteger m) {
        BigInteger r_ = Func.getZq(rand, G.getOrder());
        r.g_r = pk.g.pow(r_).getImmutable();
        h.h = pk.g.pow(Hash.H(m)).mul(pk.g.pow(Hash.H(L)).mul(pk.h).pow(r_)).getImmutable();
//        h.h = pk.g.pow(Hash.H(m)).mul(pk.g.pow(Hash.H(L))).getImmutable();
//        System.out.println(h.h);
//        System.out.println("123");
//        System.out.println(pk.g.pow(Hash.H(m).add(Hash.H(L))));
//        System.out.println("123");
//        System.out.println(pk.g.add(pk.g));
//        System.out.println("123");
//        System.out.println(pk.g.pow(Hash.H(m)));
//        System.out.println("123");
//        System.out.println(h.h.div(pk.g.pow(Hash.H(m))));
//        System.out.println("123");
//        System.out.println(pk.g);
//        System.out.println("123");
    }

    public boolean Check(HashValue h, Randomness r, PublicKey pk, BigInteger L, BigInteger m) {
//        System.out.println(h.h);
//        System.out.println("456");
//        System.out.println(pk.g.pow(Hash.H(m)));
//        System.out.println("456");
//        System.out.println(h.h.div(pk.g.pow(Hash.H(m))));
//        System.out.println(pairing.pairing(r.g_r, pk.h.mul(pk.g.pow(Hash.H(L)))));
        return pairing.pairing(pk.g, h.h.div(pk.g.pow(Hash.H(m)))).isEqual(pairing.pairing(r.g_r, pk.h.mul(pk.g.pow(Hash.H(L)))));
    }

    public void Adapt(Randomness r_p, Randomness r, PublicKey pk, SecretKey sk, BigInteger L, BigInteger m, BigInteger m_p) {
        r_p.g_r = r.g_r.mul(pk.g.pow(Hash.H(m).subtract(Hash.H(m_p)).multiply(sk.x.add(Hash.H(L)).modInverse(G.getOrder())).mod(G.getOrder()))).getImmutable();
    }
}
