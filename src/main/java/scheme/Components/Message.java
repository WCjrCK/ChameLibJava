package scheme.Components;

import utils.ElementCounter;

public abstract class Message implements scheme.CH.Components.Message, scheme.IBCH.Components.Message {
    public abstract ElementCounter TheoSize();
}
