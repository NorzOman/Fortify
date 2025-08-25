package com.facebook.react.fabric.mounting.mountitems;

import com.facebook.react.fabric.mounting.MountingManager;
import com.facebook.react.fabric.mounting.SurfaceMountingManager;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: DestroyUnmountedViewMountItem.kt */
@Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u0000\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003¢\u0006\u0004\b\u0005\u0010\u0006J\u0010\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\nH\u0016J\b\u0010\u000b\u001a\u00020\u0003H\u0016R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\f"}, d2 = {"Lcom/facebook/react/fabric/mounting/mountitems/DestroyUnmountedViewMountItem;", "Lcom/facebook/react/fabric/mounting/mountitems/MountItem;", "_surfaceId", "", "reactTag", "<init>", "(II)V", "execute", "", "mountingManager", "Lcom/facebook/react/fabric/mounting/MountingManager;", "getSurfaceId", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class DestroyUnmountedViewMountItem implements MountItem {
    private final int _surfaceId;
    private final int reactTag;

    public DestroyUnmountedViewMountItem(int i, int i2) {
        this._surfaceId = i;
        this.reactTag = i2;
    }

    @Override // com.facebook.react.fabric.mounting.mountitems.MountItem
    public void execute(MountingManager mountingManager) {
        Intrinsics.checkNotNullParameter(mountingManager, "mountingManager");
        SurfaceMountingManager surfaceManager = mountingManager.getSurfaceManager(this._surfaceId);
        if (surfaceManager == null) {
            return;
        }
        surfaceManager.deleteView(this.reactTag);
    }

    @Override // com.facebook.react.fabric.mounting.mountitems.MountItem
    /* renamed from: getSurfaceId, reason: from getter */
    public int get_surfaceId() {
        return this._surfaceId;
    }
}
