package com.facebook.fresco.ui.common;

import android.util.Log;
import com.facebook.fresco.ui.common.ControllerListener2;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ForwardingControllerListener2.kt */
@Metadata(d1 = {"\u0000D\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u0003\n\u0002\b\u0007\b\u0016\u0018\u0000 $*\u0004\b\u0000\u0010\u00012\b\u0012\u0004\u0012\u0002H\u00010\u0002:\u0001$B\u0007¢\u0006\u0004\b\u0003\u0010\u0004J\u0014\u0010\b\u001a\u00020\t2\f\u0010\n\u001a\b\u0012\u0004\u0012\u00028\u00000\u0007J\u0014\u0010\u000b\u001a\u00020\t2\f\u0010\n\u001a\b\u0012\u0004\u0012\u00028\u00000\u0007J\u0006\u0010\f\u001a\u00020\tJ+\u0010\r\u001a\u00020\t2\u0006\u0010\u000e\u001a\u00020\u000f2\u0018\u0010\u0010\u001a\u0014\u0012\n\u0012\b\u0012\u0004\u0012\u00028\u00000\u0007\u0012\u0004\u0012\u00020\t0\u0011H\u0082\bJ$\u0010\u0012\u001a\u00020\t2\u0006\u0010\u0013\u001a\u00020\u000f2\b\u0010\u0014\u001a\u0004\u0018\u00010\u00152\b\u0010\u0016\u001a\u0004\u0018\u00010\u0017H\u0016J)\u0010\u0018\u001a\u00020\t2\u0006\u0010\u0013\u001a\u00020\u000f2\b\u0010\u0019\u001a\u0004\u0018\u00018\u00002\b\u0010\u001a\u001a\u0004\u0018\u00010\u0017H\u0016¢\u0006\u0002\u0010\u001bJ$\u0010\u001c\u001a\u00020\t2\u0006\u0010\u0013\u001a\u00020\u000f2\b\u0010\u001d\u001a\u0004\u0018\u00010\u001e2\b\u0010\u0016\u001a\u0004\u0018\u00010\u0017H\u0016J\u001a\u0010\u001f\u001a\u00020\t2\u0006\u0010\u0013\u001a\u00020\u000f2\b\u0010\u0016\u001a\u0004\u0018\u00010\u0017H\u0016J\u001f\u0010 \u001a\u00020\t2\u0006\u0010\u0013\u001a\u00020\u000f2\b\u0010\u0019\u001a\u0004\u0018\u00018\u0000H\u0016¢\u0006\u0002\u0010!J\u0010\u0010\"\u001a\u00020\t2\u0006\u0010\u0013\u001a\u00020\u000fH\u0016J\u0012\u0010#\u001a\u00020\t2\b\u0010\u0014\u001a\u0004\u0018\u00010\u0015H\u0016R\u001a\u0010\u0005\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00028\u00000\u00070\u0006X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006%"}, d2 = {"Lcom/facebook/fresco/ui/common/ForwardingControllerListener2;", "I", "Lcom/facebook/fresco/ui/common/BaseControllerListener2;", "<init>", "()V", "listeners", "", "Lcom/facebook/fresco/ui/common/ControllerListener2;", "addListener", "", "listener", "removeListener", "removeAllListeners", "forEachListener", "methodName", "", "block", "Lkotlin/Function1;", "onSubmit", "id", "callerContext", "", "extras", "Lcom/facebook/fresco/ui/common/ControllerListener2$Extras;", "onFinalImageSet", "imageInfo", "extraData", "(Ljava/lang/String;Ljava/lang/Object;Lcom/facebook/fresco/ui/common/ControllerListener2$Extras;)V", "onFailure", "throwable", "", "onRelease", "onIntermediateImageSet", "(Ljava/lang/String;Ljava/lang/Object;)V", "onIntermediateImageFailed", "onEmptyEvent", "Companion", "ui-common_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public class ForwardingControllerListener2<I> extends BaseControllerListener2<I> {
    private static final String TAG = "FwdControllerListener2";
    private final List<ControllerListener2<I>> listeners = new ArrayList(2);

    public final synchronized void addListener(ControllerListener2<I> listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        this.listeners.add(listener);
    }

    public final synchronized void removeListener(ControllerListener2<I> listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        this.listeners.remove(listener);
    }

    public final synchronized void removeAllListeners() {
        this.listeners.clear();
    }

    private final void forEachListener(String methodName, Function1<? super ControllerListener2<I>, Unit> block) {
        int size = this.listeners.size();
        for (int i = 0; i < size; i++) {
            try {
                try {
                    block.invoke(this.listeners.get(i));
                    Unit unit = Unit.INSTANCE;
                } catch (Exception e) {
                    Integer.valueOf(Log.e(TAG, "InternalListener exception in " + methodName, e));
                }
            } catch (IndexOutOfBoundsException unused) {
                return;
            }
        }
    }

    @Override // com.facebook.fresco.ui.common.BaseControllerListener2, com.facebook.fresco.ui.common.ControllerListener2
    public void onSubmit(String id, Object callerContext, ControllerListener2.Extras extras) {
        Intrinsics.checkNotNullParameter(id, "id");
        int size = this.listeners.size();
        for (int i = 0; i < size; i++) {
            try {
                try {
                    this.listeners.get(i).onSubmit(id, callerContext, extras);
                    Unit unit = Unit.INSTANCE;
                } catch (Exception e) {
                    Integer.valueOf(Log.e(TAG, "InternalListener exception in onSubmit", e));
                }
            } catch (IndexOutOfBoundsException unused) {
                return;
            }
        }
    }

    @Override // com.facebook.fresco.ui.common.BaseControllerListener2, com.facebook.fresco.ui.common.ControllerListener2
    public void onFinalImageSet(String id, I imageInfo, ControllerListener2.Extras extraData) {
        Intrinsics.checkNotNullParameter(id, "id");
        int size = this.listeners.size();
        for (int i = 0; i < size; i++) {
            try {
                try {
                    this.listeners.get(i).onFinalImageSet(id, imageInfo, extraData);
                    Unit unit = Unit.INSTANCE;
                } catch (Exception e) {
                    Integer.valueOf(Log.e(TAG, "InternalListener exception in onFinalImageSet", e));
                }
            } catch (IndexOutOfBoundsException unused) {
                return;
            }
        }
    }

    @Override // com.facebook.fresco.ui.common.BaseControllerListener2, com.facebook.fresco.ui.common.ControllerListener2
    public void onFailure(String id, Throwable throwable, ControllerListener2.Extras extras) {
        Intrinsics.checkNotNullParameter(id, "id");
        int size = this.listeners.size();
        for (int i = 0; i < size; i++) {
            try {
                try {
                    this.listeners.get(i).onFailure(id, throwable, extras);
                    Unit unit = Unit.INSTANCE;
                } catch (Exception e) {
                    Integer.valueOf(Log.e(TAG, "InternalListener exception in onFailure", e));
                }
            } catch (IndexOutOfBoundsException unused) {
                return;
            }
        }
    }

    @Override // com.facebook.fresco.ui.common.BaseControllerListener2, com.facebook.fresco.ui.common.ControllerListener2
    public void onRelease(String id, ControllerListener2.Extras extras) {
        Intrinsics.checkNotNullParameter(id, "id");
        int size = this.listeners.size();
        for (int i = 0; i < size; i++) {
            try {
                try {
                    this.listeners.get(i).onRelease(id, extras);
                    Unit unit = Unit.INSTANCE;
                } catch (Exception e) {
                    Integer.valueOf(Log.e(TAG, "InternalListener exception in onRelease", e));
                }
            } catch (IndexOutOfBoundsException unused) {
                return;
            }
        }
    }

    @Override // com.facebook.fresco.ui.common.BaseControllerListener2, com.facebook.fresco.ui.common.ControllerListener2
    public void onIntermediateImageSet(String id, I imageInfo) {
        Intrinsics.checkNotNullParameter(id, "id");
        int size = this.listeners.size();
        for (int i = 0; i < size; i++) {
            try {
                try {
                    this.listeners.get(i).onIntermediateImageSet(id, imageInfo);
                    Unit unit = Unit.INSTANCE;
                } catch (Exception e) {
                    Integer.valueOf(Log.e(TAG, "InternalListener exception in onIntermediateImageSet", e));
                }
            } catch (IndexOutOfBoundsException unused) {
                return;
            }
        }
    }

    @Override // com.facebook.fresco.ui.common.BaseControllerListener2, com.facebook.fresco.ui.common.ControllerListener2
    public void onIntermediateImageFailed(String id) {
        Intrinsics.checkNotNullParameter(id, "id");
        int size = this.listeners.size();
        for (int i = 0; i < size; i++) {
            try {
                try {
                    this.listeners.get(i).onIntermediateImageFailed(id);
                    Unit unit = Unit.INSTANCE;
                } catch (Exception e) {
                    Integer.valueOf(Log.e(TAG, "InternalListener exception in onIntermediateImageFailed", e));
                }
            } catch (IndexOutOfBoundsException unused) {
                return;
            }
        }
    }

    @Override // com.facebook.fresco.ui.common.BaseControllerListener2, com.facebook.fresco.ui.common.ControllerListener2
    public void onEmptyEvent(Object callerContext) {
        int size = this.listeners.size();
        for (int i = 0; i < size; i++) {
            try {
                try {
                    this.listeners.get(i).onEmptyEvent(callerContext);
                    Unit unit = Unit.INSTANCE;
                } catch (Exception e) {
                    Integer.valueOf(Log.e(TAG, "InternalListener exception in onEmptyEvent", e));
                }
            } catch (IndexOutOfBoundsException unused) {
                return;
            }
        }
    }
}
