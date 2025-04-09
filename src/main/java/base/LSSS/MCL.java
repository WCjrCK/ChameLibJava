package base.LSSS;

import com.herumi.mcl.Fr;
import com.herumi.mcl.Mcl;
import utils.BooleanFormulaParser;

import java.util.BitSet;

public class MCL {
    public static class Matrix {
        public Fr[][] M;
        public String[] policy;
        public String formula;
        private final Fr[] Fr_tmp = new Fr[]{new Fr()};
        private final Fr ZERO = new Fr(0);

        public static class Vector {
            public Fr[] v;
        }

        public void Resize(int n, int m) {
            M = new Fr[n][m];
            for (int i = 0; i < n; i++) for (int j = 0; j < m; j++) M[i][j] = new Fr(0);
        }

        public void Prodith(Fr res, Vector y, int i) {
            res.setInt(0);
            for(int j = 0;j < M[i].length;++j) {
                Mcl.mul(Fr_tmp[0], y.v[j], M[i][j]);
                Mcl.add(res, res, Fr_tmp[0]);
            }
        }

        public void Solve(Vector x, BooleanFormulaParser.AttributeList S) {
            Vector b = new Vector();
            b.v = new Fr[M[0].length];
            for (int i = 0; i < M[0].length; i++) b.v[i] = new Fr(0);
            b.v[0].setInt(1);
            Solve(x, b, S);
        }

        public void Solve(Vector x, Vector b, BooleanFormulaParser.AttributeList S) {
            x.v = new Fr[M.length];
            for (int i = 0; i < M.length; i++) x.v[i] = new Fr(0);
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
            Fr[][] mat = new Fr[M[0].length][row_cnt + 1];
            int j = 0;
            for(int i = 0;i < M.length;++i) {
                if(tag.get(i)) {
                    for(int k = 0;k < M[i].length;++k) mat[k][j] = new Fr(M[i][k]);
                    ++j;
                }
            }
            for(int k = 0;k < M[0].length;++k) mat[k][j] = new Fr(b.v[k]);
            int main_col = 0, i = 0;
            while(main_col < row_cnt && i < mat.length) {
                if(mat[i][main_col].isZero()) {
                    for(j = i + 1;j < mat.length;++j) {
                        if(!mat[j][main_col].isZero()) {
                            Fr[] tmp = mat[j];
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
                Fr t = new Fr(mat[i][main_col]);
                for(int k = main_col;k < mat[i].length;++k) Mcl.div(mat[i][k], mat[i][k], t);
                for(j = 0;j < mat.length;++j) {
                    if(i == j || mat[j][main_col].isZero()) continue;
                    Mcl.add(t, ZERO, mat[j][main_col]);
                    for(int k = main_col;k < mat[i].length;++k) {
                        Mcl.mul(Fr_tmp[0], mat[i][k], t);
                        Mcl.sub(mat[j][k], mat[j][k], Fr_tmp[0]);
                    }
                }
                ++main_col;
                ++i;
            }
            for(i = 0;i < M.length;++i) {
                if(col_index[i] != -1) {
                    Mcl.add(x.v[col_res[i]], ZERO, mat[col_index[i]][row_cnt]);
                }
            }
        }
    }

    public void GenLSSSMatrices(Matrix M, BooleanFormulaParser.PolicyList pi, String BooleanFormulas) {
        BooleanFormulaParser BFParser = new BooleanFormulaParser(BooleanFormulas, pi);
        M.policy = new String[pi.policy.length];
        System.arraycopy(pi.policy, 0, M.policy, 0, M.policy.length);
        BFParser.SetToMCLMatrix(M);
    }
}
