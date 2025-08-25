package com.facebook.imagepipeline.producers;

import android.util.Pair;
import com.facebook.common.internal.Preconditions;
import com.facebook.common.internal.Sets;
import com.facebook.common.util.TriState;
import com.facebook.imagepipeline.common.Priority;
import com.facebook.imagepipeline.systrace.FrescoSystrace;
import java.io.Closeable;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArraySet;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public abstract class MultiplexProducer<K, T extends Closeable> implements Producer<T> {
    public static final String EXTRAS_STARTED_AS_PREFETCH = "started_as_prefetch";
    private final String mDedupedRequestsCountKey;
    private final Producer<T> mInputProducer;
    private final boolean mKeepCancelledFetchAsLowPriority;
    final Map<K, MultiplexProducer<K, T>.Multiplexer> mMultiplexers;
    private final String mProducerName;

    @Nullable
    protected abstract T cloneOrNull(@Nullable T t);

    protected abstract K getKey(ProducerContext producerContext);

    protected MultiplexProducer(Producer<T> producer, String str, String str2) {
        this(producer, str, str2, false);
    }

    protected MultiplexProducer(Producer<T> producer, String str, String str2, boolean z) {
        this.mInputProducer = producer;
        this.mMultiplexers = new HashMap();
        this.mKeepCancelledFetchAsLowPriority = z;
        this.mProducerName = str;
        this.mDedupedRequestsCountKey = str2;
    }

    @Override // com.facebook.imagepipeline.producers.Producer
    public void produceResults(Consumer<T> consumer, ProducerContext producerContext) {
        MultiplexProducer<K, T>.Multiplexer existingMultiplexer;
        boolean z;
        try {
            if (FrescoSystrace.isTracing()) {
                FrescoSystrace.beginSection("MultiplexProducer#produceResults");
            }
            producerContext.getProducerListener().onProducerStart(producerContext, this.mProducerName);
            K key = getKey(producerContext);
            do {
                synchronized (this) {
                    existingMultiplexer = getExistingMultiplexer(key);
                    if (existingMultiplexer == null) {
                        existingMultiplexer = createAndPutNewMultiplexer(key);
                        z = true;
                    } else {
                        z = false;
                    }
                }
            } while (!existingMultiplexer.addNewConsumer(consumer, producerContext));
            if (z) {
                existingMultiplexer.startInputProducerIfHasAttachedConsumers(TriState.valueOf(producerContext.isPrefetch()));
            }
        } finally {
            if (FrescoSystrace.isTracing()) {
                FrescoSystrace.endSection();
            }
        }
    }

    @Nullable
    protected synchronized MultiplexProducer<K, T>.Multiplexer getExistingMultiplexer(K k) {
        return this.mMultiplexers.get(k);
    }

    private synchronized MultiplexProducer<K, T>.Multiplexer createAndPutNewMultiplexer(K k) {
        MultiplexProducer<K, T>.Multiplexer multiplexer;
        multiplexer = new Multiplexer(k);
        this.mMultiplexers.put(k, multiplexer);
        return multiplexer;
    }

    protected synchronized void removeMultiplexer(K k, MultiplexProducer<K, T>.Multiplexer multiplexer) {
        if (this.mMultiplexers.get(k) == multiplexer) {
            this.mMultiplexers.remove(k);
        }
    }

    class Multiplexer {
        private final CopyOnWriteArraySet<Pair<Consumer<T>, ProducerContext>> mConsumerContextPairs = Sets.newCopyOnWriteArraySet();

        @Nullable
        private MultiplexProducer<K, T>.Multiplexer.ForwardingConsumer mForwardingConsumer;
        private final K mKey;

        @Nullable
        private T mLastIntermediateResult;
        private float mLastProgress;
        private int mLastStatus;

        @Nullable
        private BaseProducerContext mMultiplexProducerContext;

        public Multiplexer(K k) {
            this.mKey = k;
        }

        /* JADX WARN: Multi-variable type inference failed */
        public boolean addNewConsumer(Consumer<T> consumer, ProducerContext producerContext) {
            Pair<Consumer<T>, ProducerContext> pairCreate = Pair.create(consumer, producerContext);
            synchronized (this) {
                if (MultiplexProducer.this.getExistingMultiplexer(this.mKey) != this) {
                    return false;
                }
                this.mConsumerContextPairs.add(pairCreate);
                List<ProducerContextCallbacks> listUpdateIsPrefetch = updateIsPrefetch();
                List<ProducerContextCallbacks> listUpdatePriority = updatePriority();
                List<ProducerContextCallbacks> listUpdateIsIntermediateResultExpected = updateIsIntermediateResultExpected();
                Closeable closeableCloneOrNull = this.mLastIntermediateResult;
                float f = this.mLastProgress;
                int i = this.mLastStatus;
                BaseProducerContext.callOnIsPrefetchChanged(listUpdateIsPrefetch);
                BaseProducerContext.callOnPriorityChanged(listUpdatePriority);
                BaseProducerContext.callOnIsIntermediateResultExpectedChanged(listUpdateIsIntermediateResultExpected);
                synchronized (pairCreate) {
                    synchronized (this) {
                        if (closeableCloneOrNull != this.mLastIntermediateResult) {
                            closeableCloneOrNull = null;
                        } else if (closeableCloneOrNull != null) {
                            closeableCloneOrNull = MultiplexProducer.this.cloneOrNull(closeableCloneOrNull);
                        }
                    }
                    if (closeableCloneOrNull != null) {
                        if (f > 0.0f) {
                            consumer.onProgressUpdate(f);
                        }
                        consumer.onNewResult(closeableCloneOrNull, i);
                        closeSafely(closeableCloneOrNull);
                    }
                }
                addCallbacks(pairCreate, producerContext);
                return true;
            }
        }

        private void addCallbacks(final Pair<Consumer<T>, ProducerContext> pair, ProducerContext producerContext) {
            producerContext.addCallbacks(new BaseProducerContextCallbacks() { // from class: com.facebook.imagepipeline.producers.MultiplexProducer.Multiplexer.1
                @Override // com.facebook.imagepipeline.producers.BaseProducerContextCallbacks, com.facebook.imagepipeline.producers.ProducerContextCallbacks
                public void onCancellationRequested() {
                    boolean zRemove;
                    List list;
                    BaseProducerContext baseProducerContext;
                    List listUpdatePriority;
                    List listUpdateIsIntermediateResultExpected;
                    synchronized (Multiplexer.this) {
                        zRemove = Multiplexer.this.mConsumerContextPairs.remove(pair);
                        list = null;
                        if (!zRemove) {
                            baseProducerContext = null;
                            listUpdatePriority = null;
                        } else if (Multiplexer.this.mConsumerContextPairs.isEmpty()) {
                            baseProducerContext = Multiplexer.this.mMultiplexProducerContext;
                            listUpdatePriority = null;
                        } else {
                            List listUpdateIsPrefetch = Multiplexer.this.updateIsPrefetch();
                            listUpdatePriority = Multiplexer.this.updatePriority();
                            listUpdateIsIntermediateResultExpected = Multiplexer.this.updateIsIntermediateResultExpected();
                            baseProducerContext = null;
                            list = listUpdateIsPrefetch;
                        }
                        listUpdateIsIntermediateResultExpected = listUpdatePriority;
                    }
                    BaseProducerContext.callOnIsPrefetchChanged(list);
                    BaseProducerContext.callOnPriorityChanged(listUpdatePriority);
                    BaseProducerContext.callOnIsIntermediateResultExpectedChanged(listUpdateIsIntermediateResultExpected);
                    if (baseProducerContext != null) {
                        if (MultiplexProducer.this.mKeepCancelledFetchAsLowPriority && !baseProducerContext.isPrefetch()) {
                            BaseProducerContext.callOnPriorityChanged(baseProducerContext.setPriorityNoCallbacks(Priority.LOW));
                        } else {
                            baseProducerContext.cancel();
                        }
                    }
                    if (zRemove) {
                        ((Consumer) pair.first).onCancellation();
                    }
                }

                @Override // com.facebook.imagepipeline.producers.BaseProducerContextCallbacks, com.facebook.imagepipeline.producers.ProducerContextCallbacks
                public void onIsPrefetchChanged() {
                    BaseProducerContext.callOnIsPrefetchChanged(Multiplexer.this.updateIsPrefetch());
                }

                @Override // com.facebook.imagepipeline.producers.BaseProducerContextCallbacks, com.facebook.imagepipeline.producers.ProducerContextCallbacks
                public void onIsIntermediateResultExpectedChanged() {
                    BaseProducerContext.callOnIsIntermediateResultExpectedChanged(Multiplexer.this.updateIsIntermediateResultExpected());
                }

                @Override // com.facebook.imagepipeline.producers.BaseProducerContextCallbacks, com.facebook.imagepipeline.producers.ProducerContextCallbacks
                public void onPriorityChanged() {
                    BaseProducerContext.callOnPriorityChanged(Multiplexer.this.updatePriority());
                }
            });
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void startInputProducerIfHasAttachedConsumers(TriState triState) {
            synchronized (this) {
                boolean z = true;
                Preconditions.checkArgument(Boolean.valueOf(this.mMultiplexProducerContext == null));
                if (this.mForwardingConsumer != null) {
                    z = false;
                }
                Preconditions.checkArgument(Boolean.valueOf(z));
                if (this.mConsumerContextPairs.isEmpty()) {
                    MultiplexProducer.this.removeMultiplexer(this.mKey, this);
                    return;
                }
                ProducerContext producerContext = (ProducerContext) this.mConsumerContextPairs.iterator().next().second;
                BaseProducerContext baseProducerContext = new BaseProducerContext(producerContext.getImageRequest(), producerContext.getId(), producerContext.getProducerListener(), producerContext.getCallerContext(), producerContext.getLowestPermittedRequestLevel(), computeIsPrefetch(), computeIsIntermediateResultExpected(), computePriority(), producerContext.getImagePipelineConfig());
                this.mMultiplexProducerContext = baseProducerContext;
                baseProducerContext.putExtras(producerContext.getExtras());
                if (triState.isSet()) {
                    this.mMultiplexProducerContext.putExtra(MultiplexProducer.EXTRAS_STARTED_AS_PREFETCH, Boolean.valueOf(triState.asBoolean()));
                }
                MultiplexProducer<K, T>.Multiplexer.ForwardingConsumer forwardingConsumer = new ForwardingConsumer();
                this.mForwardingConsumer = forwardingConsumer;
                MultiplexProducer.this.mInputProducer.produceResults(forwardingConsumer, this.mMultiplexProducerContext);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        @Nullable
        public synchronized List<ProducerContextCallbacks> updateIsPrefetch() {
            BaseProducerContext baseProducerContext = this.mMultiplexProducerContext;
            if (baseProducerContext == null) {
                return null;
            }
            return baseProducerContext.setIsPrefetchNoCallbacks(computeIsPrefetch());
        }

        private synchronized boolean computeIsPrefetch() {
            Iterator<Pair<Consumer<T>, ProducerContext>> it = this.mConsumerContextPairs.iterator();
            while (it.hasNext()) {
                if (!((ProducerContext) it.next().second).isPrefetch()) {
                    return false;
                }
            }
            return true;
        }

        /* JADX INFO: Access modifiers changed from: private */
        @Nullable
        public synchronized List<ProducerContextCallbacks> updateIsIntermediateResultExpected() {
            BaseProducerContext baseProducerContext = this.mMultiplexProducerContext;
            if (baseProducerContext == null) {
                return null;
            }
            return baseProducerContext.setIsIntermediateResultExpectedNoCallbacks(computeIsIntermediateResultExpected());
        }

        private synchronized boolean computeIsIntermediateResultExpected() {
            Iterator<Pair<Consumer<T>, ProducerContext>> it = this.mConsumerContextPairs.iterator();
            while (it.hasNext()) {
                if (((ProducerContext) it.next().second).isIntermediateResultExpected()) {
                    return true;
                }
            }
            return false;
        }

        /* JADX INFO: Access modifiers changed from: private */
        @Nullable
        public synchronized List<ProducerContextCallbacks> updatePriority() {
            BaseProducerContext baseProducerContext = this.mMultiplexProducerContext;
            if (baseProducerContext == null) {
                return null;
            }
            return baseProducerContext.setPriorityNoCallbacks(computePriority());
        }

        private synchronized Priority computePriority() {
            Priority higherPriority;
            higherPriority = Priority.LOW;
            Iterator<Pair<Consumer<T>, ProducerContext>> it = this.mConsumerContextPairs.iterator();
            while (it.hasNext()) {
                higherPriority = Priority.getHigherPriority(higherPriority, ((ProducerContext) it.next().second).getPriority());
            }
            return higherPriority;
        }

        public void onFailure(MultiplexProducer<K, T>.Multiplexer.ForwardingConsumer forwardingConsumer, Throwable th) {
            synchronized (this) {
                if (this.mForwardingConsumer != forwardingConsumer) {
                    return;
                }
                Iterator<Pair<Consumer<T>, ProducerContext>> it = this.mConsumerContextPairs.iterator();
                this.mConsumerContextPairs.clear();
                MultiplexProducer.this.removeMultiplexer(this.mKey, this);
                closeSafely(this.mLastIntermediateResult);
                this.mLastIntermediateResult = null;
                while (it.hasNext()) {
                    Pair<Consumer<T>, ProducerContext> next = it.next();
                    synchronized (next) {
                        ((ProducerContext) next.second).getProducerListener().onProducerFinishWithFailure((ProducerContext) next.second, MultiplexProducer.this.mProducerName, th, null);
                        if (this.mMultiplexProducerContext != null) {
                            ((ProducerContext) next.second).putExtras(this.mMultiplexProducerContext.getExtras());
                        }
                        ((Consumer) next.first).onFailure(th);
                    }
                }
            }
        }

        public void onNextResult(MultiplexProducer<K, T>.Multiplexer.ForwardingConsumer forwardingConsumer, @Nullable T t, int i) {
            synchronized (this) {
                if (this.mForwardingConsumer != forwardingConsumer) {
                    return;
                }
                closeSafely(this.mLastIntermediateResult);
                this.mLastIntermediateResult = null;
                Iterator<Pair<Consumer<T>, ProducerContext>> it = this.mConsumerContextPairs.iterator();
                int size = this.mConsumerContextPairs.size();
                if (BaseConsumer.isNotLast(i)) {
                    this.mLastIntermediateResult = (T) MultiplexProducer.this.cloneOrNull(t);
                    this.mLastStatus = i;
                } else {
                    this.mConsumerContextPairs.clear();
                    MultiplexProducer.this.removeMultiplexer(this.mKey, this);
                }
                while (it.hasNext()) {
                    Pair<Consumer<T>, ProducerContext> next = it.next();
                    synchronized (next) {
                        if (BaseConsumer.isLast(i)) {
                            ((ProducerContext) next.second).getProducerListener().onProducerFinishWithSuccess((ProducerContext) next.second, MultiplexProducer.this.mProducerName, null);
                            if (this.mMultiplexProducerContext != null) {
                                ((ProducerContext) next.second).putExtras(this.mMultiplexProducerContext.getExtras());
                            }
                            ((ProducerContext) next.second).putExtra(MultiplexProducer.this.mDedupedRequestsCountKey, Integer.valueOf(size));
                        }
                        ((Consumer) next.first).onNewResult(t, i);
                    }
                }
            }
        }

        public void onCancelled(MultiplexProducer<K, T>.Multiplexer.ForwardingConsumer forwardingConsumer) {
            synchronized (this) {
                if (this.mForwardingConsumer != forwardingConsumer) {
                    return;
                }
                this.mForwardingConsumer = null;
                this.mMultiplexProducerContext = null;
                closeSafely(this.mLastIntermediateResult);
                this.mLastIntermediateResult = null;
                startInputProducerIfHasAttachedConsumers(TriState.UNSET);
            }
        }

        public void onProgressUpdate(MultiplexProducer<K, T>.Multiplexer.ForwardingConsumer forwardingConsumer, float f) {
            synchronized (this) {
                if (this.mForwardingConsumer != forwardingConsumer) {
                    return;
                }
                this.mLastProgress = f;
                Iterator<Pair<Consumer<T>, ProducerContext>> it = this.mConsumerContextPairs.iterator();
                while (it.hasNext()) {
                    Pair<Consumer<T>, ProducerContext> next = it.next();
                    synchronized (next) {
                        ((Consumer) next.first).onProgressUpdate(f);
                    }
                }
            }
        }

        private void closeSafely(@Nullable Closeable closeable) throws IOException {
            if (closeable != null) {
                try {
                    closeable.close();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        private class ForwardingConsumer extends BaseConsumer<T> {
            private ForwardingConsumer() {
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.facebook.imagepipeline.producers.BaseConsumer
            public void onNewResultImpl(@Nullable T t, int i) {
                try {
                    if (FrescoSystrace.isTracing()) {
                        FrescoSystrace.beginSection("MultiplexProducer#onNewResult");
                    }
                    Multiplexer.this.onNextResult(this, t, i);
                } finally {
                    if (FrescoSystrace.isTracing()) {
                        FrescoSystrace.endSection();
                    }
                }
            }

            @Override // com.facebook.imagepipeline.producers.BaseConsumer
            protected void onFailureImpl(Throwable th) {
                try {
                    if (FrescoSystrace.isTracing()) {
                        FrescoSystrace.beginSection("MultiplexProducer#onFailure");
                    }
                    Multiplexer.this.onFailure(this, th);
                } finally {
                    if (FrescoSystrace.isTracing()) {
                        FrescoSystrace.endSection();
                    }
                }
            }

            @Override // com.facebook.imagepipeline.producers.BaseConsumer
            protected void onCancellationImpl() {
                try {
                    if (FrescoSystrace.isTracing()) {
                        FrescoSystrace.beginSection("MultiplexProducer#onCancellation");
                    }
                    Multiplexer.this.onCancelled(this);
                } finally {
                    if (FrescoSystrace.isTracing()) {
                        FrescoSystrace.endSection();
                    }
                }
            }

            @Override // com.facebook.imagepipeline.producers.BaseConsumer
            protected void onProgressUpdateImpl(float f) {
                try {
                    if (FrescoSystrace.isTracing()) {
                        FrescoSystrace.beginSection("MultiplexProducer#onProgressUpdate");
                    }
                    Multiplexer.this.onProgressUpdate(this, f);
                } finally {
                    if (FrescoSystrace.isTracing()) {
                        FrescoSystrace.endSection();
                    }
                }
            }
        }
    }
}
