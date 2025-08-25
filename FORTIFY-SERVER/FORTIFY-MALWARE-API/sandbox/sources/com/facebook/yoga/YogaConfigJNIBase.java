package com.facebook.yoga;

/* loaded from: classes.dex */
public abstract class YogaConfigJNIBase extends YogaConfig {
    private YogaLogger mLogger;
    long mNativePointer;

    private YogaConfigJNIBase(long j) {
        if (j == 0) {
            throw new IllegalStateException("Failed to allocate native memory");
        }
        this.mNativePointer = j;
    }

    YogaConfigJNIBase() {
        this(YogaNative.jni_YGConfigNewJNI());
    }

    YogaConfigJNIBase(boolean z) {
        this(YogaNative.jni_YGConfigNewJNI());
    }

    @Override // com.facebook.yoga.YogaConfig
    public void setExperimentalFeatureEnabled(YogaExperimentalFeature yogaExperimentalFeature, boolean z) {
        YogaNative.jni_YGConfigSetExperimentalFeatureEnabledJNI(this.mNativePointer, yogaExperimentalFeature.intValue(), z);
    }

    @Override // com.facebook.yoga.YogaConfig
    public void setUseWebDefaults(boolean z) {
        YogaNative.jni_YGConfigSetUseWebDefaultsJNI(this.mNativePointer, z);
    }

    @Override // com.facebook.yoga.YogaConfig
    public void setPointScaleFactor(float f) {
        YogaNative.jni_YGConfigSetPointScaleFactorJNI(this.mNativePointer, f);
    }

    @Override // com.facebook.yoga.YogaConfig
    public void setErrata(YogaErrata yogaErrata) {
        YogaNative.jni_YGConfigSetErrataJNI(this.mNativePointer, yogaErrata.intValue());
    }

    @Override // com.facebook.yoga.YogaConfig
    public YogaErrata getErrata() {
        return YogaErrata.fromInt(YogaNative.jni_YGConfigGetErrataJNI(this.mNativePointer));
    }

    @Override // com.facebook.yoga.YogaConfig
    public void setLogger(YogaLogger yogaLogger) {
        this.mLogger = yogaLogger;
        YogaNative.jni_YGConfigSetLoggerJNI(this.mNativePointer, yogaLogger);
    }

    @Override // com.facebook.yoga.YogaConfig
    public YogaLogger getLogger() {
        return this.mLogger;
    }

    @Override // com.facebook.yoga.YogaConfig
    protected long getNativePointer() {
        return this.mNativePointer;
    }
}
