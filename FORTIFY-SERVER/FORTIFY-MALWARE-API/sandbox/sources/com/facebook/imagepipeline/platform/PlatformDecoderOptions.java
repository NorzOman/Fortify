package com.facebook.imagepipeline.platform;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* compiled from: PlatformDecoderOptions.kt */
@Metadata(d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0007\u0018\u00002\u00020\u0001B\u001b\u0012\b\b\u0002\u0010\u0002\u001a\u00020\u0003\u0012\b\b\u0002\u0010\u0004\u001a\u00020\u0003¢\u0006\u0004\b\u0005\u0010\u0006R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0007\u0010\bR\u0011\u0010\u0004\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\t\u0010\b¨\u0006\n"}, d2 = {"Lcom/facebook/imagepipeline/platform/PlatformDecoderOptions;", "", "avoidPoolGet", "", "avoidPoolRelease", "<init>", "(ZZ)V", "getAvoidPoolGet", "()Z", "getAvoidPoolRelease", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class PlatformDecoderOptions {
    private final boolean avoidPoolGet;
    private final boolean avoidPoolRelease;

    /* JADX WARN: Illegal instructions before constructor call */
    public PlatformDecoderOptions() {
        boolean z = false;
        this(z, z, 3, null);
    }

    public PlatformDecoderOptions(boolean z, boolean z2) {
        this.avoidPoolGet = z;
        this.avoidPoolRelease = z2;
    }

    public /* synthetic */ PlatformDecoderOptions(boolean z, boolean z2, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? false : z, (i & 2) != 0 ? false : z2);
    }

    public final boolean getAvoidPoolGet() {
        return this.avoidPoolGet;
    }

    public final boolean getAvoidPoolRelease() {
        return this.avoidPoolRelease;
    }
}
