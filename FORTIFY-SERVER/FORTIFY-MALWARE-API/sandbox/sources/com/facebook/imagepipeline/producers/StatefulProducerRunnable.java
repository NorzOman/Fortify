package com.facebook.imagepipeline.producers;

import com.facebook.common.executors.StatefulRunnable;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: StatefulProducerRunnable.kt */
@Metadata(d1 = {"\u0000>\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010$\n\u0002\b\b\b&\u0018\u0000*\u0004\b\u0000\u0010\u00012\b\u0012\u0004\u0012\u0002H\u00010\u0002B-\u0012\f\u0010\u0003\u001a\b\u0012\u0004\u0012\u00028\u00000\u0004\u0012\u0006\u0010\u0005\u001a\u00020\u0006\u0012\u0006\u0010\u0007\u001a\u00020\b\u0012\u0006\u0010\t\u001a\u00020\n¢\u0006\u0004\b\u000b\u0010\fJ\u0017\u0010\r\u001a\u00020\u000e2\b\u0010\u000f\u001a\u0004\u0018\u00018\u0000H\u0014¢\u0006\u0002\u0010\u0010J\u0010\u0010\u0011\u001a\u00020\u000e2\u0006\u0010\u0012\u001a\u00020\u0013H\u0014J\b\u0010\u0014\u001a\u00020\u000eH\u0014J)\u0010\u0015\u001a\u0014\u0012\u0006\u0012\u0004\u0018\u00010\n\u0012\u0006\u0012\u0004\u0018\u00010\n\u0018\u00010\u00162\b\u0010\u000f\u001a\u0004\u0018\u00018\u0000H\u0014¢\u0006\u0002\u0010\u0017J \u0010\u0018\u001a\u0010\u0012\u0004\u0012\u00020\n\u0012\u0004\u0012\u00020\n\u0018\u00010\u00162\b\u0010\u0019\u001a\u0004\u0018\u00010\u0013H\u0014J\u0017\u0010\u001d\u001a\u00020\u000e2\b\u0010\u000f\u001a\u0004\u0018\u00018\u0000H$¢\u0006\u0002\u0010\u0010R\u0014\u0010\u0003\u001a\b\u0012\u0004\u0012\u00028\u00000\u0004X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0005\u001a\u00020\u0006X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0007\u001a\u00020\bX\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\t\u001a\u00020\nX\u0082\u0004¢\u0006\u0002\n\u0000R\"\u0010\u001a\u001a\u0010\u0012\u0004\u0012\u00020\n\u0012\u0004\u0012\u00020\n\u0018\u00010\u00168TX\u0094\u0004¢\u0006\u0006\u001a\u0004\b\u001b\u0010\u001c¨\u0006\u001e"}, d2 = {"Lcom/facebook/imagepipeline/producers/StatefulProducerRunnable;", "T", "Lcom/facebook/common/executors/StatefulRunnable;", "consumer", "Lcom/facebook/imagepipeline/producers/Consumer;", "producerListener", "Lcom/facebook/imagepipeline/producers/ProducerListener2;", "producerContext", "Lcom/facebook/imagepipeline/producers/ProducerContext;", "producerName", "", "<init>", "(Lcom/facebook/imagepipeline/producers/Consumer;Lcom/facebook/imagepipeline/producers/ProducerListener2;Lcom/facebook/imagepipeline/producers/ProducerContext;Ljava/lang/String;)V", "onSuccess", "", "result", "(Ljava/lang/Object;)V", "onFailure", "e", "Ljava/lang/Exception;", "onCancellation", "getExtraMapOnSuccess", "", "(Ljava/lang/Object;)Ljava/util/Map;", "getExtraMapOnFailure", "exception", "extraMapOnCancellation", "getExtraMapOnCancellation", "()Ljava/util/Map;", "disposeResult", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public abstract class StatefulProducerRunnable<T> extends StatefulRunnable<T> {
    private final Consumer<T> consumer;
    private final ProducerContext producerContext;
    private final ProducerListener2 producerListener;
    private final String producerName;

    @Override // com.facebook.common.executors.StatefulRunnable
    protected abstract void disposeResult(T result);

    protected Map<String, String> getExtraMapOnCancellation() {
        return null;
    }

    protected Map<String, String> getExtraMapOnFailure(Exception exception) {
        return null;
    }

    protected Map<String, String> getExtraMapOnSuccess(T result) {
        return null;
    }

    public StatefulProducerRunnable(Consumer<T> consumer, ProducerListener2 producerListener, ProducerContext producerContext, String producerName) {
        Intrinsics.checkNotNullParameter(consumer, "consumer");
        Intrinsics.checkNotNullParameter(producerListener, "producerListener");
        Intrinsics.checkNotNullParameter(producerContext, "producerContext");
        Intrinsics.checkNotNullParameter(producerName, "producerName");
        this.consumer = consumer;
        this.producerListener = producerListener;
        this.producerContext = producerContext;
        this.producerName = producerName;
        producerListener.onProducerStart(producerContext, producerName);
    }

    @Override // com.facebook.common.executors.StatefulRunnable
    protected void onSuccess(T result) {
        ProducerListener2 producerListener2 = this.producerListener;
        ProducerContext producerContext = this.producerContext;
        String str = this.producerName;
        producerListener2.onProducerFinishWithSuccess(producerContext, str, producerListener2.requiresExtraMap(producerContext, str) ? getExtraMapOnSuccess(result) : null);
        this.consumer.onNewResult(result, 1);
    }

    @Override // com.facebook.common.executors.StatefulRunnable
    protected void onFailure(Exception e) {
        Intrinsics.checkNotNullParameter(e, "e");
        ProducerListener2 producerListener2 = this.producerListener;
        ProducerContext producerContext = this.producerContext;
        String str = this.producerName;
        Exception exc = e;
        producerListener2.onProducerFinishWithFailure(producerContext, str, exc, producerListener2.requiresExtraMap(producerContext, str) ? getExtraMapOnFailure(e) : null);
        this.consumer.onFailure(exc);
    }

    @Override // com.facebook.common.executors.StatefulRunnable
    protected void onCancellation() {
        ProducerListener2 producerListener2 = this.producerListener;
        ProducerContext producerContext = this.producerContext;
        String str = this.producerName;
        producerListener2.onProducerFinishWithCancellation(producerContext, str, producerListener2.requiresExtraMap(producerContext, str) ? getExtraMapOnCancellation() : null);
        this.consumer.onCancellation();
    }
}
