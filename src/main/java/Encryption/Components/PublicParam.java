package Encryption.Components;

import utils.ElementCounter;

import java.util.Map;

public abstract class PublicParam {
    protected PublicParam(Map<String, Object> params) {}

    public abstract ElementCounter TheoSize();
}
