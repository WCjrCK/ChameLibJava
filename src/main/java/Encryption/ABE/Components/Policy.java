package Encryption.ABE.Components;

import EllipticCurve.Curve.Curve;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

import java.util.BitSet;

public class Policy {
    public static class Vector {
        public Scalar[] v;
    }

    public Scalar[][] M;
    public String[] policy;
    public String formula;

    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }

    public void Solve(Vector x, Curve curve, Attributes S) {
        Vector b = new Vector();
        b.v = new Scalar[M[0].length];
        b.v[0] = curve.getOneScalar();
        for (int i = 1; i < M[0].length; i++) b.v[i] = curve.getZeroScalar();
        Solve(x, b, curve, S);
    }

    public void Solve(Vector x, Vector b, Curve curve, Attributes S) {
        x.v = new Scalar[M.length];
        for (int i = 0; i < M.length; i++) x.v[i] = curve.getZeroScalar();
        if(b.v.length != M[0].length) return;
        BitSet tag = new BitSet(M.length);
        int[] col_res = new int[M.length];
        int[] col_index = new int[M.length];
        for(int i = 0; i < M.length; i++) col_index[i] = -1;
        int row_cnt = 0;
        for(int i = 0;i < policy.length;++i) {
            if(S.attrs.contains(policy[i])) {
                tag.set(i);
                col_res[row_cnt] = i;
                ++row_cnt;
            }
        }
        Scalar[][] mat = new Scalar[M[0].length][row_cnt + 1];
        int j = 0;
        for(int i = 0;i < M.length;++i) {
            if(tag.get(i)) {
                for(int k = 0;k < M[i].length;++k) mat[k][j] = M[i][k];
                ++j;
            }
        }
        for(int k = 0;k < M[0].length;++k) mat[k][j] = b.v[k];
        int main_col = 0, i = 0;
        while(main_col < row_cnt && i < mat.length) {
            if(mat[i][main_col].isZero()) {
                for(j = i + 1;j < mat.length;++j) {
                    if(!mat[j][main_col].isZero()) {
                        Scalar[] tmp = mat[j];
                        mat[j] = mat[i];
                        mat[i] = tmp;
                        break;
                    }
                }
            }
            if(mat[i][main_col].isZero()) {
                ++main_col;
                continue;
            }
            col_index[main_col] = i;
            Scalar t = mat[i][main_col];
            for(int k = main_col;k < mat[i].length;++k) mat[i][k] = mat[i][k].div(t);
            for(j = 0;j < mat.length;++j) {
                if(i == j || mat[j][main_col].isZero()) continue;
                t = mat[j][main_col];
                for(int k = main_col;k < mat[i].length;++k) mat[j][k] = mat[j][k].sub(mat[i][k].mul(t));
            }
            ++main_col;
            ++i;
        }
        for(i = 0;i < M.length;++i) {
            if(col_index[i] != -1) {
                x.v[col_res[i]] = mat[col_index[i]][row_cnt];
            }
        }
    }
}
