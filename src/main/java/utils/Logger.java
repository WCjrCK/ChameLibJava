package utils;

import it.unisa.dia.gas.jpbc.Element;

public class Logger {
    public static void Print(String name, Element element){
        System.out.println(name);
        System.out.println(element.toBytes());
    }
}
