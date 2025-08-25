package com.facebook.imagepipeline.systrace;

import android.os.Trace;
import com.facebook.imagepipeline.systrace.FrescoSystrace;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: DefaultFrescoSystrace.kt */
@Metadata(d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0002\u0018\u00002\u00020\u0001:\u0001\rB\u0007¢\u0006\u0004\b\u0002\u0010\u0003J\u0010\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H\u0016J\u0010\u0010\b\u001a\u00020\t2\u0006\u0010\u0006\u001a\u00020\u0007H\u0016J\b\u0010\n\u001a\u00020\u0005H\u0016J\b\u0010\u000b\u001a\u00020\fH\u0016¨\u0006\u000e"}, d2 = {"Lcom/facebook/imagepipeline/systrace/DefaultFrescoSystrace;", "Lcom/facebook/imagepipeline/systrace/FrescoSystrace$Systrace;", "<init>", "()V", "beginSection", "", "name", "", "beginSectionWithArgs", "Lcom/facebook/imagepipeline/systrace/FrescoSystrace$ArgsBuilder;", "endSection", "isTracing", "", "DefaultArgsBuilder", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class DefaultFrescoSystrace implements FrescoSystrace.Systrace {
    @Override // com.facebook.imagepipeline.systrace.FrescoSystrace.Systrace
    public boolean isTracing() {
        return false;
    }

    @Override // com.facebook.imagepipeline.systrace.FrescoSystrace.Systrace
    public void beginSection(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        if (isTracing()) {
            Trace.beginSection(name);
        }
    }

    @Override // com.facebook.imagepipeline.systrace.FrescoSystrace.Systrace
    public FrescoSystrace.ArgsBuilder beginSectionWithArgs(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        if (isTracing()) {
            return new DefaultArgsBuilder(name);
        }
        return FrescoSystrace.NO_OP_ARGS_BUILDER;
    }

    @Override // com.facebook.imagepipeline.systrace.FrescoSystrace.Systrace
    public void endSection() {
        if (isTracing()) {
            Trace.endSection();
        }
    }

    /* compiled from: DefaultFrescoSystrace.kt */
    @Metadata(d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\u0010\t\n\u0002\u0010\u0006\n\u0002\b\u0004\b\u0002\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\b\u0010\n\u001a\u00020\u000bH\u0016J\u0018\u0010\f\u001a\u00020\u00002\u0006\u0010\r\u001a\u00020\u00032\u0006\u0010\u000e\u001a\u00020\u000fH\u0016J\u0018\u0010\f\u001a\u00020\u00002\u0006\u0010\r\u001a\u00020\u00032\u0006\u0010\u000e\u001a\u00020\u0010H\u0016J\u0018\u0010\f\u001a\u00020\u00002\u0006\u0010\r\u001a\u00020\u00032\u0006\u0010\u000e\u001a\u00020\u0011H\u0016J\u0018\u0010\f\u001a\u00020\u00002\u0006\u0010\r\u001a\u00020\u00032\u0006\u0010\u000e\u001a\u00020\u0012H\u0016J%\u0010\u0013\u001a\n \u0014*\u0004\u0018\u00010\b0\b2\u0006\u0010\r\u001a\u00020\u00032\u0006\u0010\u000e\u001a\u00020\u000fH\u0002¢\u0006\u0002\u0010\u0015R\u0014\u0010\u0006\u001a\u00060\bj\u0002`\u0007X\u0082\u0004¢\u0006\u0004\n\u0002\u0010\t¨\u0006\u0016"}, d2 = {"Lcom/facebook/imagepipeline/systrace/DefaultFrescoSystrace$DefaultArgsBuilder;", "Lcom/facebook/imagepipeline/systrace/FrescoSystrace$ArgsBuilder;", "name", "", "<init>", "(Ljava/lang/String;)V", "stringBuilder", "Lkotlin/text/StringBuilder;", "Ljava/lang/StringBuilder;", "Ljava/lang/StringBuilder;", "flush", "", "arg", "key", "value", "", "", "", "", "appendArgument", "kotlin.jvm.PlatformType", "(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/StringBuilder;", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    private static final class DefaultArgsBuilder implements FrescoSystrace.ArgsBuilder {
        private final StringBuilder stringBuilder;

        public DefaultArgsBuilder(String name) {
            Intrinsics.checkNotNullParameter(name, "name");
            this.stringBuilder = new StringBuilder(name);
        }

        @Override // com.facebook.imagepipeline.systrace.FrescoSystrace.ArgsBuilder
        public void flush() {
            if (this.stringBuilder.length() > 127) {
                this.stringBuilder.setLength(127);
            }
            Trace.beginSection(this.stringBuilder.toString());
        }

        @Override // com.facebook.imagepipeline.systrace.FrescoSystrace.ArgsBuilder
        public DefaultArgsBuilder arg(String key, Object value) {
            Intrinsics.checkNotNullParameter(key, "key");
            Intrinsics.checkNotNullParameter(value, "value");
            appendArgument(key, value);
            return this;
        }

        @Override // com.facebook.imagepipeline.systrace.FrescoSystrace.ArgsBuilder
        public DefaultArgsBuilder arg(String key, int value) {
            Intrinsics.checkNotNullParameter(key, "key");
            appendArgument(key, Integer.valueOf(value));
            return this;
        }

        @Override // com.facebook.imagepipeline.systrace.FrescoSystrace.ArgsBuilder
        public DefaultArgsBuilder arg(String key, long value) {
            Intrinsics.checkNotNullParameter(key, "key");
            appendArgument(key, Long.valueOf(value));
            return this;
        }

        @Override // com.facebook.imagepipeline.systrace.FrescoSystrace.ArgsBuilder
        public DefaultArgsBuilder arg(String key, double value) {
            Intrinsics.checkNotNullParameter(key, "key");
            appendArgument(key, Double.valueOf(value));
            return this;
        }

        private final StringBuilder appendArgument(String key, Object value) {
            return this.stringBuilder.append(';').append(key + "=" + value);
        }
    }
}
