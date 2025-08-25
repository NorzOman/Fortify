package com.facebook.yoga;

/* loaded from: classes.dex */
public class YogaConfigJNIFinalizer extends YogaConfigJNIBase {
    protected void finalize() throws Throwable {
        try {
            freeNatives();
        } finally {
            super.finalize();
        }
    }

    public void freeNatives() {
        if (this.mNativePointer != 0) {
            long j = this.mNativePointer;
            this.mNativePointer = 0L;
            YogaNative.jni_YGConfigFreeJNI(j);
        }
    }
}
