package MathStructure;

import EllipticCurve.Curve.Curve;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.Components.Attributes;
import utils.ElementCounter;

import java.util.BitSet;

public class LSSS {
    public Scalar[][] M;
    public String[] policy;
    public String formula;

    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }

    public Scalar[] Solve(Curve curve, Attributes S) {
        Scalar[] b = new Scalar[M[0].length];
        b[0] = curve.getOneScalar();
        for (int i = 1; i < M[0].length; i++) b[i] = curve.getZeroScalar();
        return Solve(b, curve, S);
    }

    public Scalar[] Solve(Scalar[] b, Curve curve, Attributes S) {
        Scalar[] x = new Scalar[M.length];
        for (int i = 0; i < M.length; i++) x[i] = curve.getZeroScalar();
        if(b.length != M[0].length) return null;
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
        for(int k = 0;k < M[0].length;++k) mat[k][j] = b[k];
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
                x[col_res[i]] = mat[col_index[i]][row_cnt];
            }
        }
        return x;
    }
}
