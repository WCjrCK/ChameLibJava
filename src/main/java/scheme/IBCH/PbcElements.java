package scheme.IBCH;

import it.unisa.dia.gas.jpbc.Element;

public class PbcElements {
    private Element[] elements;

    public void init(int n){
        if(elements != null && elements.length > 0){
            // already initialized
            return;
        }
        elements = new Element[n];
    }
    public void init_same_as(PbcElements other){
        if(elements != null && elements.length > 0){
            // already initialized
            return;
        }
        init(other.elements.length);
    }

    // public PbcElements(PbcElements other){
    //     if (this == other) return;
        
    //     elements = new Element[other.elements.length];
    //     for(int i = 0; i < other.elements.length; i++){
    //         elements[i] = other.elements[i].duplicate();
    //     }
    // }
    
    public Element get(int index){
        return elements[index];
    }
    public Element get(Enum enum_index){
        return elements[enum_index.ordinal()];
    }

    public void set(int index, Element element){
        elements[index] = element.duplicate();
    }
    public void set(Enum enum_index, Element element){
        elements[enum_index.ordinal()] = element.duplicate();
    }

    public int getSize(){
        return elements.length;
    }

    public boolean equals(PbcElements other){
        if (this == other) return true;
        if (elements.length != other.elements.length) return false;
        for(int i = 0; i < elements.length; i++){
            if(!elements[i].isEqual(other.elements[i])){
                return false;
            }
        }
        return true;
    }
            
    public void print(){
        System.out.println(this.getClass().getSimpleName() + " elements:");
        for(int i = 0; i < elements.length; i++){
            print(i);
        }
    }
    public void print(int index){
        System.out.println("Element " + index + ": ");
        System.out.println(elements[index].toBytes());
    }
}
