package com.facebook.react.fabric.mounting.mountitems;

import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.uimanager.StateWrapper;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MountItemFactory.kt */
@Metadata(d1 = {"\u0000N\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0010\u0015\n\u0000\n\u0002\u0010\u0011\n\u0002\b\u0003\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J*\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u00072\u0006\u0010\t\u001a\u00020\u00072\b\u0010\n\u001a\u0004\u0018\u00010\u000bH\u0007J*\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u00072\u0006\u0010\t\u001a\u00020\f2\b\u0010\n\u001a\u0004\u0018\u00010\u000bH\u0007J \u0010\r\u001a\u00020\u000e2\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u00072\u0006\u0010\u000f\u001a\u00020\u0007H\u0007J<\u0010\u0010\u001a\u00020\u000e2\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u00072\u0006\u0010\u0011\u001a\u00020\f2\b\u0010\u0012\u001a\u0004\u0018\u00010\u00132\b\u0010\u0014\u001a\u0004\u0018\u00010\u00152\u0006\u0010\u0016\u001a\u00020\u0017H\u0007J\u0018\u0010\u0018\u001a\u00020\u000e2\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u0007H\u0007J5\u0010\u0019\u001a\u00020\u000e2\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\u001a\u001a\u00020\u001b2\u000e\u0010\u001c\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00010\u001d2\u0006\u0010\u001e\u001a\u00020\u0007H\u0007¢\u0006\u0002\u0010\u001f¨\u0006 "}, d2 = {"Lcom/facebook/react/fabric/mounting/mountitems/MountItemFactory;", "", "<init>", "()V", "createDispatchCommandMountItem", "Lcom/facebook/react/fabric/mounting/mountitems/DispatchCommandMountItem;", "surfaceId", "", "reactTag", "commandId", "commandArgs", "Lcom/facebook/react/bridge/ReadableArray;", "", "createSendAccessibilityEventMountItem", "Lcom/facebook/react/fabric/mounting/mountitems/MountItem;", "eventType", "createPreAllocateViewMountItem", "component", "props", "Lcom/facebook/react/bridge/ReadableMap;", "stateWrapper", "Lcom/facebook/react/uimanager/StateWrapper;", "isLayoutable", "", "createDestroyViewMountItem", "createIntBufferBatchMountItem", "intBuf", "", "objBuf", "", "commitNumber", "(I[I[Ljava/lang/Object;I)Lcom/facebook/react/fabric/mounting/mountitems/MountItem;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class MountItemFactory {
    public static final MountItemFactory INSTANCE = new MountItemFactory();

    private MountItemFactory() {
    }

    @JvmStatic
    public static final DispatchCommandMountItem createDispatchCommandMountItem(int surfaceId, int reactTag, int commandId, ReadableArray commandArgs) {
        return new DispatchIntCommandMountItem(surfaceId, reactTag, commandId, commandArgs);
    }

    @JvmStatic
    public static final DispatchCommandMountItem createDispatchCommandMountItem(int surfaceId, int reactTag, String commandId, ReadableArray commandArgs) {
        Intrinsics.checkNotNullParameter(commandId, "commandId");
        return new DispatchStringCommandMountItem(surfaceId, reactTag, commandId, commandArgs);
    }

    @JvmStatic
    public static final MountItem createSendAccessibilityEventMountItem(int surfaceId, int reactTag, int eventType) {
        return new SendAccessibilityEventMountItem(surfaceId, reactTag, eventType);
    }

    @JvmStatic
    public static final MountItem createPreAllocateViewMountItem(int surfaceId, int reactTag, String component, ReadableMap props, StateWrapper stateWrapper, boolean isLayoutable) {
        Intrinsics.checkNotNullParameter(component, "component");
        return new PreAllocateViewMountItem(surfaceId, reactTag, component, props, stateWrapper, isLayoutable);
    }

    @JvmStatic
    public static final MountItem createDestroyViewMountItem(int surfaceId, int reactTag) {
        return new DestroyUnmountedViewMountItem(surfaceId, reactTag);
    }

    @JvmStatic
    public static final MountItem createIntBufferBatchMountItem(int surfaceId, int[] intBuf, Object[] objBuf, int commitNumber) {
        Intrinsics.checkNotNullParameter(intBuf, "intBuf");
        Intrinsics.checkNotNullParameter(objBuf, "objBuf");
        return new IntBufferBatchMountItem(surfaceId, intBuf, objBuf, commitNumber);
    }
}
