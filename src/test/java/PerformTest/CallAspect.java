package PerformTest;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.Point;
import EllipticCurve.Point.Scalar;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;

@Aspect
public class CallAspect {
    @Around(
            "(" +
                    "execution(* ChameleonHash.CH..*.Setup(..))" +
                    " || execution(* ChameleonHash.CH..*.KeyGen(..))" +
                    " || execution(* ChameleonHash.CH..*.Hash(..))" +
                    " || execution(* ChameleonHash.CH..*.Verify(..))" +
                    " || execution(* ChameleonHash.CH..*.Collision(..))" +
                    ")" +
                    " && !execution(* EllipticCurve..*(..))" +
                    " && !within(PerformTest..*)"
    )
    public Object aroundAllCHStage(ProceedingJoinPoint pjp) throws Throwable {
//        System.out.println("CH running: " + pjp.getSignature().toString());
        if (TraceScope.CountFunc()) TraceScope.hit("use " + pjp.getSignature().getName() + " of BlackBox CH scheme");
        TraceScope.enter();
        Object ret_val = pjp.proceed();
        TraceScope.exit();
        return ret_val;
    }

    @Around(
            "(" +
                    "execution(* ChameleonHash.IBCH..*.Setup(..))" +
                    " || execution(* ChameleonHash.IBCH..*.KeyGen(..))" +
                    " || execution(* ChameleonHash.IBCH..*.Hash(..))" +
                    " || execution(* ChameleonHash.IBCH..*.Verify(..))" +
                    " || execution(* ChameleonHash.IBCH..*.Collision(..))" +
                    ")" +
                    " && !execution(* EllipticCurve..*(..))" +
                    " && !within(PerformTest..*)"
    )
    public Object aroundAllIBCHStage(ProceedingJoinPoint pjp) throws Throwable {
//        System.out.println("IBCH running: " + pjp.getSignature().toString());
        if (TraceScope.CountFunc()) TraceScope.hit("use " + pjp.getSignature().getName() + " of BlackBox IBCH scheme");
        TraceScope.enter();
        Object ret_val = pjp.proceed();
        TraceScope.exit();
        return ret_val;
    }

    @Around(
            "(" +
                    "execution(* ChameleonHash.PBCH..*.Setup(..))" +
                    " || execution(* ChameleonHash.PBCH..*.KeyGen(..))" +
                    " || execution(* ChameleonHash.PBCH..*.Hash(..))" +
                    " || execution(* ChameleonHash.PBCH..*.Verify(..))" +
                    " || execution(* ChameleonHash.PBCH..*.Collision(..))" +
                    ")" +
                    " && !execution(* EllipticCurve..*(..))" +
                    " && !within(PerformTest..*)"
    )
    public Object aroundAllPBCHStage(ProceedingJoinPoint pjp) throws Throwable {
//        System.out.println("PBCH running: " + pjp.getSignature().toString());
        if (TraceScope.CountFunc()) TraceScope.hit("use " + pjp.getSignature().getName() + " of BlackBox PBCH scheme");
        TraceScope.enter();
        Object ret_val = pjp.proceed();
        TraceScope.exit();
        return ret_val;
    }

    @Around(
            "(" +
                    "execution(* Encryption.ABE.FAME..*.Setup(..))" +
                    " || execution(* Encryption.ABE.FAME..*.KeyGen(..))" +
                    " || execution(* Encryption.ABE.FAME..*.Encrypt(..))" +
                    " || execution(* Encryption.ABE.FAME..*.Decrypt(..))" +
                    ")" +
                    " && !execution(* EllipticCurve..*(..))" +
                    " && !within(PerformTest..*)"
    )
    public Object aroundAllFAMEStage(ProceedingJoinPoint pjp) throws Throwable {
//        System.out.println("FAME running: " + pjp.getSignature().toString());
        if (TraceScope.CountFunc()) TraceScope.hit("use " + pjp.getSignature().getName() + " of BlackBox FAME scheme");
        TraceScope.enter();
        Object ret_val = pjp.proceed();
        TraceScope.exit();
        return ret_val;
    }

    @Around(
            "(" +
                    "execution(* Encryption.PKE..Setup(..))" +
                    " || execution(* Encryption.PKE..KeyGen(..))" +
                    " || execution(* Encryption.PKE..Encrypt(..))" +
                    " || execution(* Encryption.PKE..Decrypt(..))" +
                    ")" +
                    " && !execution(* ChameleonHash..*(..))" +
                    " && !execution(* EllipticCurve..*(..))" +
                    " && !within(PerformTest..*)"
    )
    public Object aroundAllPKEStage(ProceedingJoinPoint pjp) throws Throwable {
//        System.out.println("PKE running: " + pjp.getSignature().toString());
        if (TraceScope.CountFunc()) TraceScope.hit("use " + pjp.getSignature().getName() + " of BlackBox PKE scheme");
        TraceScope.enter();
//        TraceScope.hit();
        Object ret_val = pjp.proceed();
        TraceScope.exit();
        return ret_val;
    }

    @Around(
            "(" +
                    "execution(* Commitment..NIZK*..Commitment(..))" +
                    " || execution(* Commitment..Proof..Check(..))" +
                    ")" +
                    " && !execution(* ChameleonHash..*(..))" +
                    " && !execution(* EllipticCurve..*(..))" +
                    " && !within(PerformTest..*)"
    )
    public Object aroundAllNIZKStage(ProceedingJoinPoint pjp) throws Throwable {
//        System.out.println("NIZK running: " + pjp.getSignature().toString());
        String funcName = pjp.getSignature().toString();
        if (funcName.contains("NIZK_DL")) {
            if (funcName.contains(".Commitment(")) TraceScope.hit("make DL commitment with BlackBox NIZK scheme");
            if (funcName.contains(".Check(")) TraceScope.hit("check DL commitment with BlackBox NIZK scheme");
        } else if (funcName.contains("NIZK_DH_PAIR")) {
            if (funcName.contains(".Commitment(")) TraceScope.hit("make DH_PAIR commitment with BlackBox NIZK scheme");
            if (funcName.contains(".Check(")) TraceScope.hit("check DH_PAIR commitment with BlackBox NIZK scheme");
        } else {
            if (TraceScope.CountFunc()) TraceScope.hit(funcName);
        }
//        TraceScope.hit("use " + pjp.getSignature().getName() + " of BlackBox PKE scheme");
        TraceScope.enter();
//        TraceScope.hit();
        Object ret_val = pjp.proceed();
        TraceScope.exit();
        return ret_val;
    }

    @Around(
            "(" +
                    "execution(* EllipticCurve.Point..*.*Core(..))" +
//                    " || execution(* EllipticCurve.Curve..*.createPoint(..))" +
//                    " || execution(* EllipticCurve.Curve..*.createScalar(..))" +
                    " || execution(protected * EllipticCurve.Curve..*.Pairing(..))" +
                    " || execution(* EllipticCurve.Curve..*.getRandom*(..))" +
                    " || execution(* ChameleonHash..PublicParam+.H*(..))" +
            ")" +
            " && !execution(* *.toString(..))" +
            " && !execution(* *.hashCode(..))" +
            " && !execution(* *.equals(..))" +
            " && !within(PerformTest..*)"
    )
    public Object countBaseInst(ProceedingJoinPoint pjp) throws Throwable {
        if (!TraceScope.active()) return pjp.proceed();
        Object target = pjp.getTarget();
        Object[] args = pjp.getArgs();
        String method = pjp.getSignature().toString();
        String key = method;
        Object ret_val = pjp.proceed();

        if (method.contains("getRandom")) {
            if (method.contains("getRandomPoint")) {
                if (args[0] instanceof CurveGroup) key = "Random in " + ((CurveGroup) args[0]).name();
            } else if (method.contains("getRandomScalar")) key = "Random in Zp";
        } else if (method.contains("PublicParam.H")) {
            if (ret_val instanceof Point<?, ?>) key = "Hash to " + ((Point<?, ?>) ret_val).group();
            else if (ret_val instanceof Scalar<?>) key = "Hash to Zp";
        } else if (method.contains("Pairing")) key = "Pairing";
        else if (method.contains("addCore") || method.contains("subCore") || method.contains("negCore")) {
            if (target instanceof Point<?, ?>) key = "Mul in " + ((Point<?, ?>) target).group();
            else if (ret_val instanceof Scalar<?>) key = "Mul in Zp";
        }
        else if (method.contains("mulCore") || method.contains("divCore")) {
            if (target instanceof Point<?, ?>) key = "Pow in " + ((Point<?, ?>) target).group();
            else if (ret_val instanceof Scalar<?>) key = "Pow in Zp";
        }
        TraceScope.hit(key);
        return ret_val;
    }
}
