package com.facebook.imagepipeline.systrace;

import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: FrescoSystrace.kt */
@Metadata(d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0007\bÆ\u0002\u0018\u00002\u00020\u0001:\u0003\u0019\u001a\u001bB\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0012\u0010\u0006\u001a\u00020\u00072\b\u0010\b\u001a\u0004\u0018\u00010\tH\u0007J\u0010\u0010\n\u001a\u00020\u00072\u0006\u0010\u000b\u001a\u00020\fH\u0007J\u0010\u0010\r\u001a\u00020\u00052\u0006\u0010\u000b\u001a\u00020\fH\u0007J\b\u0010\u000e\u001a\u00020\u0007H\u0007J-\u0010\u000f\u001a\u0002H\u0010\"\u0004\b\u0000\u0010\u00102\u0006\u0010\u000b\u001a\u00020\f2\f\u0010\u0011\u001a\b\u0012\u0004\u0012\u0002H\u00100\u0012H\u0086\bø\u0001\u0000¢\u0006\u0002\u0010\u0013J\b\u0010\u0014\u001a\u00020\u0015H\u0007R\u0010\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u0016\u001a\u0004\u0018\u00010\tX\u0082\u000e¢\u0006\u0002\n\u0000R\u0014\u0010\b\u001a\u00020\t8BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\u0017\u0010\u0018\u0082\u0002\u0007\n\u0005\b\u009920\u0001¨\u0006\u001c"}, d2 = {"Lcom/facebook/imagepipeline/systrace/FrescoSystrace;", "", "<init>", "()V", "NO_OP_ARGS_BUILDER", "Lcom/facebook/imagepipeline/systrace/FrescoSystrace$ArgsBuilder;", "provide", "", "instance", "Lcom/facebook/imagepipeline/systrace/FrescoSystrace$Systrace;", "beginSection", "name", "", "beginSectionWithArgs", "endSection", "traceSection", "T", "block", "Lkotlin/Function0;", "(Ljava/lang/String;Lkotlin/jvm/functions/Function0;)Ljava/lang/Object;", "isTracing", "", "_instance", "getInstance", "()Lcom/facebook/imagepipeline/systrace/FrescoSystrace$Systrace;", "Systrace", "ArgsBuilder", "NoOpArgsBuilder", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class FrescoSystrace {
    public static final FrescoSystrace INSTANCE = new FrescoSystrace();
    public static final ArgsBuilder NO_OP_ARGS_BUILDER = new NoOpArgsBuilder();
    private static Systrace _instance;

    /* compiled from: FrescoSystrace.kt */
    @Metadata(d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\b\n\u0002\u0010\t\n\u0002\u0010\u0006\n\u0000\bf\u0018\u00002\u00020\u0001J\b\u0010\u0002\u001a\u00020\u0003H&J\u0018\u0010\u0004\u001a\u00020\u00002\u0006\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\u0001H&J\u0018\u0010\u0004\u001a\u00020\u00002\u0006\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\bH&J\u0018\u0010\u0004\u001a\u00020\u00002\u0006\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\tH&J\u0018\u0010\u0004\u001a\u00020\u00002\u0006\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\nH&¨\u0006\u000b"}, d2 = {"Lcom/facebook/imagepipeline/systrace/FrescoSystrace$ArgsBuilder;", "", "flush", "", "arg", "key", "", "value", "", "", "", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public interface ArgsBuilder {
        ArgsBuilder arg(String key, double value);

        ArgsBuilder arg(String key, int value);

        ArgsBuilder arg(String key, long value);

        ArgsBuilder arg(String key, Object value);

        void flush();
    }

    /* compiled from: FrescoSystrace.kt */
    @Metadata(d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0000\bf\u0018\u00002\u00020\u0001J\u0010\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\u0006\u001a\u00020\u00072\u0006\u0010\u0004\u001a\u00020\u0005H&J\b\u0010\b\u001a\u00020\u0003H&J\b\u0010\t\u001a\u00020\nH&¨\u0006\u000b"}, d2 = {"Lcom/facebook/imagepipeline/systrace/FrescoSystrace$Systrace;", "", "beginSection", "", "name", "", "beginSectionWithArgs", "Lcom/facebook/imagepipeline/systrace/FrescoSystrace$ArgsBuilder;", "endSection", "isTracing", "", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public interface Systrace {
        void beginSection(String name);

        ArgsBuilder beginSectionWithArgs(String name);

        void endSection();

        boolean isTracing();
    }

    private FrescoSystrace() {
    }

    @JvmStatic
    public static final void provide(Systrace instance) {
        _instance = instance;
    }

    @JvmStatic
    public static final void beginSection(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        INSTANCE.getInstance().beginSection(name);
    }

    @JvmStatic
    public static final ArgsBuilder beginSectionWithArgs(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        return INSTANCE.getInstance().beginSectionWithArgs(name);
    }

    @JvmStatic
    public static final void endSection() {
        INSTANCE.getInstance().endSection();
    }

    public final <T> T traceSection(String name, Function0<? extends T> block) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(block, "block");
        if (!isTracing()) {
            return block.invoke();
        }
        beginSection(name);
        try {
            return block.invoke();
        } finally {
            endSection();
        }
    }

    @JvmStatic
    public static final boolean isTracing() {
        return INSTANCE.getInstance().isTracing();
    }

    private final Systrace getInstance() {
        DefaultFrescoSystrace defaultFrescoSystrace;
        Systrace systrace = _instance;
        if (systrace != null) {
            return systrace;
        }
        synchronized (FrescoSystrace.class) {
            defaultFrescoSystrace = new DefaultFrescoSystrace();
            _instance = defaultFrescoSystrace;
        }
        return defaultFrescoSystrace;
    }

    /* compiled from: FrescoSystrace.kt */
    @Metadata(d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\u0010\t\n\u0002\u0010\u0006\n\u0000\b\u0002\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0002\u0010\u0003J\b\u0010\u0004\u001a\u00020\u0005H\u0016J\u0018\u0010\u0006\u001a\u00020\u00012\u0006\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\nH\u0016J\u0018\u0010\u0006\u001a\u00020\u00012\u0006\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\u000bH\u0016J\u0018\u0010\u0006\u001a\u00020\u00012\u0006\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\fH\u0016J\u0018\u0010\u0006\u001a\u00020\u00012\u0006\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\rH\u0016¨\u0006\u000e"}, d2 = {"Lcom/facebook/imagepipeline/systrace/FrescoSystrace$NoOpArgsBuilder;", "Lcom/facebook/imagepipeline/systrace/FrescoSystrace$ArgsBuilder;", "<init>", "()V", "flush", "", "arg", "key", "", "value", "", "", "", "", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    private static final class NoOpArgsBuilder implements ArgsBuilder {
        @Override // com.facebook.imagepipeline.systrace.FrescoSystrace.ArgsBuilder
        public void flush() {
        }

        @Override // com.facebook.imagepipeline.systrace.FrescoSystrace.ArgsBuilder
        public ArgsBuilder arg(String key, Object value) {
            Intrinsics.checkNotNullParameter(key, "key");
            Intrinsics.checkNotNullParameter(value, "value");
            return this;
        }

        @Override // com.facebook.imagepipeline.systrace.FrescoSystrace.ArgsBuilder
        public ArgsBuilder arg(String key, int value) {
            Intrinsics.checkNotNullParameter(key, "key");
            return this;
        }

        @Override // com.facebook.imagepipeline.systrace.FrescoSystrace.ArgsBuilder
        public ArgsBuilder arg(String key, long value) {
            Intrinsics.checkNotNullParameter(key, "key");
            return this;
        }

        @Override // com.facebook.imagepipeline.systrace.FrescoSystrace.ArgsBuilder
        public ArgsBuilder arg(String key, double value) {
            Intrinsics.checkNotNullParameter(key, "key");
            return this;
        }
    }
}
