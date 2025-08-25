package com.facebook.react.fabric.mounting.mountitems;

import com.facebook.react.bridge.ReactSoftExceptionLogger;
import com.facebook.react.bridge.RetryableMountingLayerException;
import com.facebook.react.fabric.mounting.MountingManager;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: SendAccessibilityEvent.kt */
@Metadata(d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\b\u0000\u0018\u00002\u00020\u0001B\u001f\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0003¢\u0006\u0004\b\u0006\u0010\u0007J\u0010\u0010\n\u001a\u00020\u000b2\u0006\u0010\f\u001a\u00020\rH\u0016J\b\u0010\u000e\u001a\u00020\u0003H\u0016J\b\u0010\u000f\u001a\u00020\tH\u0016R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0005\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\b\u001a\u00020\tX\u0082D¢\u0006\u0002\n\u0000¨\u0006\u0010"}, d2 = {"Lcom/facebook/react/fabric/mounting/mountitems/SendAccessibilityEvent;", "Lcom/facebook/react/fabric/mounting/mountitems/MountItem;", "_surfaceId", "", "reactTag", "eventType", "<init>", "(III)V", "TAG", "", "execute", "", "mountingManager", "Lcom/facebook/react/fabric/mounting/MountingManager;", "getSurfaceId", "toString", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class SendAccessibilityEvent implements MountItem {
    private final String TAG = "Fabric.SendAccessibilityEvent";
    private final int _surfaceId;
    private final int eventType;
    private final int reactTag;

    public SendAccessibilityEvent(int i, int i2, int i3) {
        this._surfaceId = i;
        this.reactTag = i2;
        this.eventType = i3;
    }

    @Override // com.facebook.react.fabric.mounting.mountitems.MountItem
    public void execute(MountingManager mountingManager) {
        Intrinsics.checkNotNullParameter(mountingManager, "mountingManager");
        try {
            mountingManager.sendAccessibilityEvent(this._surfaceId, this.reactTag, this.eventType);
        } catch (RetryableMountingLayerException e) {
            ReactSoftExceptionLogger.logSoftException(this.TAG, e);
        }
    }

    @Override // com.facebook.react.fabric.mounting.mountitems.MountItem
    /* renamed from: getSurfaceId, reason: from getter */
    public int get_surfaceId() {
        return this._surfaceId;
    }

    public String toString() {
        return "SendAccessibilityEvent [" + this.reactTag + "] " + this.eventType;
    }
}
