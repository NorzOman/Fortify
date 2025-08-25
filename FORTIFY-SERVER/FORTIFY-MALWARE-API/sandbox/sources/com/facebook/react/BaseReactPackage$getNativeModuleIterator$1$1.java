package com.facebook.react;

import com.facebook.react.BaseReactPackage;
import com.facebook.react.bridge.ModuleHolder;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.internal.featureflags.ReactNativeFeatureFlags;
import com.facebook.react.module.model.ReactModuleInfo;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import kotlin.Metadata;
import kotlin.jvm.internal.markers.KMappedMarker;

/* compiled from: BaseReactPackage.kt */
@Metadata(d1 = {"\u0000-\n\u0000\n\u0002\u0010(\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010&\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002*\u0001\u0000\b\n\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001J\b\u0010\u000b\u001a\u00020\fH\u0002J\t\u0010\r\u001a\u00020\u000eH\u0096\u0002J\t\u0010\u000f\u001a\u00020\u0002H\u0096\u0002R(\u0010\u0003\u001a\u0010\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0007\u0010\b\"\u0004\b\t\u0010\n¨\u0006\u0010"}, d2 = {"com/facebook/react/BaseReactPackage$getNativeModuleIterator$1$1", "", "Lcom/facebook/react/bridge/ModuleHolder;", "nextEntry", "", "", "Lcom/facebook/react/module/model/ReactModuleInfo;", "getNextEntry", "()Ljava/util/Map$Entry;", "setNextEntry", "(Ljava/util/Map$Entry;)V", "findNext", "", "hasNext", "", "next", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class BaseReactPackage$getNativeModuleIterator$1$1 implements Iterator<ModuleHolder>, KMappedMarker {
    final /* synthetic */ Iterator<Map.Entry<String, ReactModuleInfo>> $entrySetIterator;
    final /* synthetic */ ReactApplicationContext $reactContext;
    private Map.Entry<String, ReactModuleInfo> nextEntry;
    final /* synthetic */ BaseReactPackage this$0;

    @Override // java.util.Iterator
    public void remove() {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    /* JADX WARN: Multi-variable type inference failed */
    BaseReactPackage$getNativeModuleIterator$1$1(Iterator<? extends Map.Entry<String, ReactModuleInfo>> it, BaseReactPackage baseReactPackage, ReactApplicationContext reactApplicationContext) {
        this.$entrySetIterator = it;
        this.this$0 = baseReactPackage;
        this.$reactContext = reactApplicationContext;
    }

    public final Map.Entry<String, ReactModuleInfo> getNextEntry() {
        return this.nextEntry;
    }

    public final void setNextEntry(Map.Entry<String, ReactModuleInfo> entry) {
        this.nextEntry = entry;
    }

    private final void findNext() {
        while (this.$entrySetIterator.hasNext()) {
            Map.Entry<String, ReactModuleInfo> next = this.$entrySetIterator.next();
            ReactModuleInfo value = next.getValue();
            if (!ReactNativeFeatureFlags.useTurboModules() || !value.getIsTurboModule()) {
                this.nextEntry = next;
                return;
            }
        }
        this.nextEntry = null;
    }

    @Override // java.util.Iterator
    public boolean hasNext() {
        if (this.nextEntry == null) {
            findNext();
        }
        return this.nextEntry != null;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // java.util.Iterator
    public ModuleHolder next() {
        if (this.nextEntry == null) {
            findNext();
        }
        Map.Entry<String, ReactModuleInfo> entry = this.nextEntry;
        if (entry == null) {
            throw new NoSuchElementException("ModuleHolder not found");
        }
        findNext();
        return new ModuleHolder(entry.getValue(), new BaseReactPackage.ModuleHolderProvider(this.this$0, entry.getKey(), this.$reactContext));
    }
}
