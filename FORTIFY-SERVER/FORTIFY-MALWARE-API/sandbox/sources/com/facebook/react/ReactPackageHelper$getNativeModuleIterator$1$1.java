package com.facebook.react;

import com.facebook.react.bridge.ModuleHolder;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.uimanager.ViewProps;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.markers.KMappedMarker;

/* compiled from: ReactPackageHelper.kt */
@Metadata(d1 = {"\u0000\u001d\n\u0000\n\u0002\u0010(\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0010\u000b\n\u0000*\u0001\u0000\b\n\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001J\t\u0010\t\u001a\u00020\u0002H\u0096\u0002J\t\u0010\n\u001a\u00020\u000bH\u0096\u0002R\u001a\u0010\u0003\u001a\u00020\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0005\u0010\u0006\"\u0004\b\u0007\u0010\b¨\u0006\f"}, d2 = {"com/facebook/react/ReactPackageHelper$getNativeModuleIterator$1$1", "", "Lcom/facebook/react/bridge/ModuleHolder;", ViewProps.POSITION, "", "getPosition", "()I", "setPosition", "(I)V", "next", "hasNext", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ReactPackageHelper$getNativeModuleIterator$1$1 implements Iterator<ModuleHolder>, KMappedMarker {
    final /* synthetic */ List<NativeModule> $nativeModules;
    private int position;

    @Override // java.util.Iterator
    public void remove() {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    /* JADX WARN: Multi-variable type inference failed */
    ReactPackageHelper$getNativeModuleIterator$1$1(List<? extends NativeModule> list) {
        this.$nativeModules = list;
    }

    public final int getPosition() {
        return this.position;
    }

    public final void setPosition(int i) {
        this.position = i;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // java.util.Iterator
    public ModuleHolder next() {
        List<NativeModule> list = this.$nativeModules;
        int i = this.position;
        this.position = i + 1;
        return new ModuleHolder(list.get(i));
    }

    @Override // java.util.Iterator
    public boolean hasNext() {
        return this.position < this.$nativeModules.size();
    }
}
