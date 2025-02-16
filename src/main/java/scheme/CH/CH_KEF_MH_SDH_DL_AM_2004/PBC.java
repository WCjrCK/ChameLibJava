package scheme.CH.CH_KEF_MH_SDH_DL_AM_2004;

/*
 * On the Key Exposure Problem in Chameleon Hashes
 * P12. Scheme based on SDH and DL
 */

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;
import utils.Hash;

import java.math.BigInteger;
import java.util.Random;

@SuppressWarnings("rawtypes")
public class PBC {
    public static class PublicKey {
        public Element h, g;
    }

    public static class SecretKey {
        public BigInteger x;
    }

    public static class HashValue {
        public Element h;
    }

    public static class Randomness {
        public Element g_r;
    }


    Random rand = new Random();
    Pairing pairing;
    Field G;

    public PBC(curve.PBC curve) {
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
    }

    public boolean Check(HashValue h, Randomness r, PublicKey pk, BigInteger L, BigInteger m) {
        return pairing.pairing(pk.g, h.h.div(pk.g.pow(Hash.H(m)))).isEqual(pairing.pairing(r.g_r, pk.h.mul(pk.g.pow(Hash.H(L)))));
    }

    public void Adapt(Randomness r_p, Randomness r, PublicKey pk, SecretKey sk, BigInteger L, BigInteger m, BigInteger m_p) {
        r_p.g_r = r.g_r.mul(pk.g.pow(Hash.H(m).subtract(Hash.H(m_p)).multiply(sk.x.add(Hash.H(L)).modInverse(G.getOrder())).mod(G.getOrder()))).getImmutable();
    }
}
