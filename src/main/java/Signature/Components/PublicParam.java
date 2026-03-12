package Signature.Components;

import utils.ElementCounter;

import java.util.Map;

public abstract class PublicParam {

    public abstract Message createMessage(String msg);

    protected PublicParam(Map<String, Object> params) {}

    public abstract ElementCounter TheoSize();
}
