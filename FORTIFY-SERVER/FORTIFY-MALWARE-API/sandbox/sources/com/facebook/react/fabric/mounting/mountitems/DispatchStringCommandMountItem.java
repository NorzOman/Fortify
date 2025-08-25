package com.facebook.react.fabric.mounting.mountitems;

import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.fabric.mounting.MountingManager;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: DispatchStringCommandMountItem.kt */
@Metadata(d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u0000\u0018\u00002\u00020\u0001B)\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0006\u0012\b\u0010\u0007\u001a\u0004\u0018\u00010\b¢\u0006\u0004\b\t\u0010\nJ\b\u0010\u000b\u001a\u00020\u0003H\u0016J\u0010\u0010\f\u001a\u00020\r2\u0006\u0010\u000e\u001a\u00020\u000fH\u0016J\b\u0010\u0010\u001a\u00020\u0006H\u0016R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0005\u001a\u00020\u0006X\u0082\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u0007\u001a\u0004\u0018\u00010\bX\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0011"}, d2 = {"Lcom/facebook/react/fabric/mounting/mountitems/DispatchStringCommandMountItem;", "Lcom/facebook/react/fabric/mounting/mountitems/DispatchCommandMountItem;", "surfaceId", "", "reactTag", "commandId", "", "commandArgs", "Lcom/facebook/react/bridge/ReadableArray;", "<init>", "(IILjava/lang/String;Lcom/facebook/react/bridge/ReadableArray;)V", "getSurfaceId", "execute", "", "mountingManager", "Lcom/facebook/react/fabric/mounting/MountingManager;", "toString", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class DispatchStringCommandMountItem extends DispatchCommandMountItem {
    private final ReadableArray commandArgs;
    private final String commandId;
    private final int reactTag;
    private final int surfaceId;

    public DispatchStringCommandMountItem(int i, int i2, String commandId, ReadableArray readableArray) {
        Intrinsics.checkNotNullParameter(commandId, "commandId");
        this.surfaceId = i;
        this.reactTag = i2;
        this.commandId = commandId;
        this.commandArgs = readableArray;
    }

    @Override // com.facebook.react.fabric.mounting.mountitems.MountItem
    public int getSurfaceId() {
        return this.surfaceId;
    }

    @Override // com.facebook.react.fabric.mounting.mountitems.MountItem
    public void execute(MountingManager mountingManager) {
        Intrinsics.checkNotNullParameter(mountingManager, "mountingManager");
        mountingManager.receiveCommand(this.surfaceId, this.reactTag, this.commandId, this.commandArgs);
    }

    public String toString() {
        return "DispatchStringCommandMountItem [" + this.reactTag + "] " + this.commandId;
    }
}
