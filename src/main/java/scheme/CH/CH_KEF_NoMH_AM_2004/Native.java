package scheme.CH.CH_KEF_NoMH_AM_2004;

/*
* On the Key Exposure Problem in Chameleon Hashes
* P7. Key Exposure Freeness Without Message Hiding
*/

import utils.Func;
import utils.Hash;

import java.math.BigInteger;
import java.util.Random;

public class Native {
    public static class PublicKey {
        public BigInteger p, q, g, y;
    }

    public static class SecretKey {
        public BigInteger x;
    }

    public static class HashValue {
        public BigInteger h;
    }

    public static class Randomness {
        public BigInteger r, s;
    }

    Random rand = new Random();

    private BigInteger getHashValue(Randomness R, PublicKey pk, BigInteger m) {
        return R.r.subtract(pk.y.modPow(Hash.H(m, R.r), pk.p).multiply(pk.g.modPow(R.s, pk.p)).mod(pk.p)).mod(pk.q);
    }

    public void KeyGen(PublicKey pk, SecretKey sk, int k) {
        do {
            pk.q = BigInteger.probablePrime(k, rand);
            pk.p = pk.q.multiply(BigInteger.TWO).add(BigInteger.ONE);
        } while (!pk.p.isProbablePrime(100));
        do {
            pk.g = new BigInteger(pk.p.bitLength(), rand).mod(pk.p);
        } while (pk.g.modPow(pk.q, pk.p).compareTo(BigInteger.ONE) != 0);
        sk.x = Func.getZq(rand, pk.q);
        pk.y = pk.g.modPow(sk.x, pk.p);
    }

    public void Hash(HashValue H, Randomness R, PublicKey pk, BigInteger m) {
        R.r = Func.getZq(rand, pk.q);
        R.s = Func.getZq(rand, pk.q);
        H.h = getHashValue(R, pk, m);
    }

    public boolean Check(HashValue H, Randomness R, PublicKey pk, BigInteger m) {
        return H.h.compareTo(getHashValue(R, pk, m)) == 0;
    }

    public void Adapt(Randomness R_p, HashValue H, PublicKey pk, SecretKey sk, BigInteger m_p) {
        BigInteger k_p = Func.getZq(rand, pk.q);
        R_p.r = H.h.add(pk.g.modPow(k_p, pk.p)).mod(pk.q);
        R_p.s = k_p.subtract(Hash.H(m_p, R_p.r).multiply(sk.x)).mod(pk.q);
    }
}
