package com.facebook.jni;

import java.util.Iterator;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class IteratorHelper {

    @Nullable
    private Object mElement;
    private final Iterator mIterator;

    public IteratorHelper(Iterator it) {
        this.mIterator = it;
    }

    public IteratorHelper(Iterable iterable) {
        this.mIterator = iterable.iterator();
    }

    boolean hasNext() {
        if (this.mIterator.hasNext()) {
            this.mElement = this.mIterator.next();
            return true;
        }
        this.mElement = null;
        return false;
    }
}
