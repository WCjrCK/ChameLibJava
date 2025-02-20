package base.LSSS;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import utils.BooleanFormulaParser;

import java.util.Arrays;

@SuppressWarnings("rawtypes")
public class PBC {
    public static class Matrix {
        public Field G;
        public Element[][] M;

        public Matrix(Field G) {
            this.G = G;
        }

        public void Resize(int n, int m) {
            M = new Element[n][m];
        }

        public void Print() {
            System.out.println("Matrix:");
            for (Element[] elements : M) {
                System.out.println(Arrays.toString(elements));
            }
            System.out.println();
        }
    }

    public void GenLSSSMatrices(Matrix M, BooleanFormulaParser.PolicyList pi, String BooleanFormulas) {
        BooleanFormulaParser BFParser = new BooleanFormulaParser(BooleanFormulas, pi);
        BFParser.SetToPBCMatrix(M);
    }
}
