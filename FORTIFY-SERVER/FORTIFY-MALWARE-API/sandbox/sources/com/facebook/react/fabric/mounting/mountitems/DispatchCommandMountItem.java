package com.facebook.react.fabric.mounting.mountitems;

import kotlin.Metadata;

/* compiled from: DispatchCommandMountItem.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\b&\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0002\u0010\u0003J\b\u0010\u0006\u001a\u00020\u0007H\u0007J\b\u0010\b\u001a\u00020\u0005H\u0007R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u000e¢\u0006\u0002\n\u0000¨\u0006\t"}, d2 = {"Lcom/facebook/react/fabric/mounting/mountitems/DispatchCommandMountItem;", "Lcom/facebook/react/fabric/mounting/mountitems/MountItem;", "<init>", "()V", "numRetries", "", "incrementRetries", "", "getRetries", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public abstract class DispatchCommandMountItem implements MountItem {
    private int numRetries;

    public final void incrementRetries() {
        this.numRetries++;
    }

    /* renamed from: getRetries, reason: from getter */
    public final int getNumRetries() {
        return this.numRetries;
    }
}
