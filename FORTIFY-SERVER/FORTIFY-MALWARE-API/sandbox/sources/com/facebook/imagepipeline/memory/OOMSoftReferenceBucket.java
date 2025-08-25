package com.facebook.imagepipeline.memory;

import com.facebook.common.internal.Preconditions;
import com.facebook.common.references.OOMSoftReference;
import java.util.LinkedList;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
class OOMSoftReferenceBucket<V> extends Bucket<V> {
    private LinkedList<OOMSoftReference<V>> mSpareReferences;

    public OOMSoftReferenceBucket(int i, int i2, int i3) {
        super(i, i2, i3, false);
        this.mSpareReferences = new LinkedList<>();
    }

    @Override // com.facebook.imagepipeline.memory.Bucket
    @Nullable
    public V pop() {
        OOMSoftReference<V> oOMSoftReference = (OOMSoftReference) this.mFreeList.poll();
        Preconditions.checkNotNull(oOMSoftReference);
        V v = oOMSoftReference.get();
        oOMSoftReference.clear();
        this.mSpareReferences.add(oOMSoftReference);
        return v;
    }

    @Override // com.facebook.imagepipeline.memory.Bucket
    void addToFreeList(V v) {
        OOMSoftReference<V> oOMSoftReferencePoll = this.mSpareReferences.poll();
        if (oOMSoftReferencePoll == null) {
            oOMSoftReferencePoll = new OOMSoftReference<>();
        }
        oOMSoftReferencePoll.set(v);
        this.mFreeList.add(oOMSoftReferencePoll);
    }
}
