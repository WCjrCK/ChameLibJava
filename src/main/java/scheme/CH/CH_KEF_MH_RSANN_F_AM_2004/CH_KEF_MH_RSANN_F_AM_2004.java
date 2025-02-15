package scheme.CH.CH_KEF_MH_RSANN_F_AM_2004;

/*
 * On the Key Exposure Problem in Chameleon Hashes
 * P10. Scheme based on RSA[n,n] and Factoring
 */

import utils.Func;
import utils.Hash;

import java.math.BigInteger;
import java.util.Random;

public class CH_KEF_MH_RSANN_F_AM_2004 {
    Random rand = new Random();

    private BigInteger getHashValue(Randomness r, PublicKey pk, BigInteger L, BigInteger m) {
        BigInteger mod_n2 = pk.n.pow(2);
        return m.multiply(pk.n).add(BigInteger.ONE).multiply(Hash.H(L).modPow(r.r_1, mod_n2).multiply(r.r_2.modPow(pk.n, mod_n2))).mod(mod_n2);
    }

    private BigInteger L(BigInteger x, BigInteger n) {
        return x.subtract(BigInteger.ONE).divide(n);
    }

    public void KeyGen(PublicKey pk, SecretKey sk, int bit_len) {
        sk.p = BigInteger.probablePrime(bit_len, rand);
        sk.q = BigInteger.probablePrime(bit_len, rand);
        pk.n = sk.p.multiply(sk.q);
    }

    public void Hash(HashValue h, Randomness r, PublicKey pk, BigInteger L, BigInteger m) {
        r.r_1 = Func.getZq(rand, pk.n);
        r.r_2 = Func.getZq(rand, pk.n);
        h.h = getHashValue(r, pk, L, m);
    }

    public boolean Check(HashValue h, Randomness r, PublicKey pk, BigInteger L, BigInteger m) {
        return h.h.compareTo(getHashValue(r, pk, L, m)) == 0;
    }

    public void Adapt(Randomness r_p, HashValue h, PublicKey pk, SecretKey sk, BigInteger L, BigInteger m_p) {
        BigInteger mod_n2 = pk.n.pow(2);
        BigInteger C_p = h.h.multiply(BigInteger.ONE.subtract(m_p.multiply(pk.n))).mod(mod_n2);
        BigInteger lambda = Func.lcm(sk.p.subtract(BigInteger.ONE), sk.q.subtract(BigInteger.ONE));
        BigInteger h_ = Hash.H(L);
        r_p.r_1 = L(C_p.modPow(lambda, mod_n2), pk.n).multiply(L(h_.modPow(lambda, mod_n2), pk.n).modInverse(pk.n)).mod(pk.n);
        r_p.r_2 = h.h.multiply(h_.modPow(r_p.r_1.negate(), pk.n)).modPow(pk.n.modInverse(lambda), pk.n);
    }
}
