package com.facebook.react;

import com.facebook.react.bridge.ModuleHolder;
import com.facebook.react.bridge.ReactApplicationContext;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.jvm.internal.markers.KMappedMarker;

/* compiled from: Iterables.kt */
@Metadata(d1 = {"\u0000\u0011\n\u0000\n\u0002\u0010\u001c\n\u0000\n\u0002\u0010(\n\u0000*\u0001\u0000\b\n\u0018\u00002\b\u0012\u0004\u0012\u00028\u00000\u0001J\u000f\u0010\u0002\u001a\b\u0012\u0004\u0012\u00028\u00000\u0003H\u0096\u0002¨\u0006\u0004¸\u0006\u0000"}, d2 = {"kotlin/collections/CollectionsKt__IterablesKt$Iterable$1", "", "iterator", "", "kotlin-stdlib"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class BaseReactPackage$getNativeModuleIterator$$inlined$Iterable$1 implements Iterable<ModuleHolder>, KMappedMarker {
    final /* synthetic */ Iterator $entrySetIterator$inlined;
    final /* synthetic */ ReactApplicationContext $reactContext$inlined;
    final /* synthetic */ BaseReactPackage this$0;

    public BaseReactPackage$getNativeModuleIterator$$inlined$Iterable$1(Iterator it, BaseReactPackage baseReactPackage, ReactApplicationContext reactApplicationContext) {
        this.$entrySetIterator$inlined = it;
        this.this$0 = baseReactPackage;
        this.$reactContext$inlined = reactApplicationContext;
    }

    @Override // java.lang.Iterable
    public Iterator<ModuleHolder> iterator() {
        return new BaseReactPackage$getNativeModuleIterator$1$1(this.$entrySetIterator$inlined, this.this$0, this.$reactContext$inlined);
    }
}
