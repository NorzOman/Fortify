package com.facebook.hermes.instrumentation;

import com.facebook.soloader.SoLoader;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;

/* compiled from: HermesSamplingProfiler.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\t\u0010\u0004\u001a\u00020\u0005H\u0087 J\t\u0010\u0006\u001a\u00020\u0005H\u0087 J\u0011\u0010\u0007\u001a\u00020\u00052\u0006\u0010\b\u001a\u00020\tH\u0087 ¨\u0006\n"}, d2 = {"Lcom/facebook/hermes/instrumentation/HermesSamplingProfiler;", "", "<init>", "()V", "enable", "", "disable", "dumpSampledTraceToFile", "filename", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class HermesSamplingProfiler {
    public static final HermesSamplingProfiler INSTANCE = new HermesSamplingProfiler();

    @JvmStatic
    public static final native void disable();

    @JvmStatic
    public static final native void dumpSampledTraceToFile(String filename);

    @JvmStatic
    public static final native void enable();

    private HermesSamplingProfiler() {
    }

    static {
        SoLoader.loadLibrary("jsijniprofiler");
    }
}
