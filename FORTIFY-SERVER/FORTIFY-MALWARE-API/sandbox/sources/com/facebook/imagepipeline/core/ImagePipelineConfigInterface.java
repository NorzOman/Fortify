package com.facebook.imagepipeline.core;

import android.content.Context;
import android.graphics.Bitmap;
import com.facebook.cache.common.CacheKey;
import com.facebook.cache.disk.DiskCacheConfig;
import com.facebook.callercontext.CallerContextVerifier;
import com.facebook.common.executors.SerialExecutorService;
import com.facebook.common.internal.Supplier;
import com.facebook.common.memory.MemoryTrimmableRegistry;
import com.facebook.common.memory.PooledByteBuffer;
import com.facebook.imagepipeline.bitmaps.PlatformBitmapFactory;
import com.facebook.imagepipeline.cache.BitmapMemoryCacheFactory;
import com.facebook.imagepipeline.cache.CacheKeyFactory;
import com.facebook.imagepipeline.cache.CountingMemoryCache;
import com.facebook.imagepipeline.cache.ImageCacheStatsTracker;
import com.facebook.imagepipeline.cache.MemoryCache;
import com.facebook.imagepipeline.cache.MemoryCacheParams;
import com.facebook.imagepipeline.debug.CloseableReferenceLeakTracker;
import com.facebook.imagepipeline.decoder.ImageDecoder;
import com.facebook.imagepipeline.decoder.ImageDecoderConfig;
import com.facebook.imagepipeline.decoder.ProgressiveJpegConfig;
import com.facebook.imagepipeline.image.CloseableImage;
import com.facebook.imagepipeline.listener.RequestListener;
import com.facebook.imagepipeline.listener.RequestListener2;
import com.facebook.imagepipeline.memory.PoolFactory;
import com.facebook.imagepipeline.producers.CustomProducerSequenceFactory;
import com.facebook.imagepipeline.producers.NetworkFetcher;
import com.facebook.imagepipeline.transcoder.ImageTranscoderFactory;
import java.util.Map;
import java.util.Set;
import kotlin.Metadata;

/* compiled from: ImagePipelineConfigInterface.kt */
@Metadata(d1 = {"\u0000\u009e\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010$\n\u0002\u0010\u000e\n\u0002\b\u0003\bf\u0018\u00002\u00020\u0001R\u0014\u0010\u0002\u001a\u0004\u0018\u00010\u0003X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0004\u0010\u0005R\u0018\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\b0\u0007X¦\u0004¢\u0006\u0006\u001a\u0004\b\t\u0010\nR\u0012\u0010\u000b\u001a\u00020\fX¦\u0004¢\u0006\u0006\u001a\u0004\b\r\u0010\u000eR\u0012\u0010\u000f\u001a\u00020\fX¦\u0004¢\u0006\u0006\u001a\u0004\b\u0010\u0010\u000eR\u001a\u0010\u0011\u001a\n\u0012\u0004\u0012\u00020\u0013\u0018\u00010\u0012X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0014\u0010\u0015R\u0012\u0010\u0016\u001a\u00020\u0017X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0018\u0010\u0019R\u0012\u0010\u001a\u001a\u00020\u001bX¦\u0004¢\u0006\u0006\u001a\u0004\b\u001c\u0010\u001dR\u0018\u0010\u001e\u001a\b\u0012\u0004\u0012\u00020\u001f0\u0007X¦\u0004¢\u0006\u0006\u001a\u0004\b \u0010\nR\u0012\u0010!\u001a\u00020\"X¦\u0004¢\u0006\u0006\u001a\u0004\b#\u0010$R\u0012\u0010%\u001a\u00020&X¦\u0004¢\u0006\u0006\u001a\u0004\b%\u0010'R\u0018\u0010(\u001a\b\u0012\u0004\u0012\u00020\b0\u0007X¦\u0004¢\u0006\u0006\u001a\u0004\b)\u0010\nR\u0012\u0010*\u001a\u00020+X¦\u0004¢\u0006\u0006\u001a\u0004\b,\u0010-R\u0014\u0010.\u001a\u0004\u0018\u00010/X¦\u0004¢\u0006\u0006\u001a\u0004\b0\u00101R\u0012\u00102\u001a\u000203X¦\u0004¢\u0006\u0006\u001a\u0004\b4\u00105R\u0014\u00106\u001a\u0004\u0018\u000107X¦\u0004¢\u0006\u0006\u001a\u0004\b8\u00109R\u0014\u0010:\u001a\u0004\u0018\u00010;X¦\u0004¢\u0006\u0006\u001a\u0004\b<\u0010=R\u0014\u0010>\u001a\u0004\u0018\u00010?X¦\u0004¢\u0006\u0006\u001a\u0004\b@\u0010AR\u0018\u0010B\u001a\b\u0012\u0004\u0012\u00020&0\u0007X¦\u0004¢\u0006\u0006\u001a\u0004\bB\u0010\nR\u0018\u0010C\u001a\b\u0012\u0004\u0012\u00020&0\u0007X¦\u0004¢\u0006\u0006\u001a\u0004\bD\u0010\nR\u0012\u0010E\u001a\u00020FX¦\u0004¢\u0006\u0006\u001a\u0004\bG\u0010HR\u0012\u0010I\u001a\u00020JX¦\u0004¢\u0006\u0006\u001a\u0004\bK\u0010LR\u0012\u0010M\u001a\u00020?X¦\u0004¢\u0006\u0006\u001a\u0004\bN\u0010OR\u0016\u0010P\u001a\u0006\u0012\u0002\b\u00030QX¦\u0004¢\u0006\u0006\u001a\u0004\bR\u0010SR\u0014\u0010T\u001a\u0004\u0018\u00010UX¦\u0004¢\u0006\u0006\u001a\u0004\bV\u0010WR\u0012\u0010X\u001a\u00020YX¦\u0004¢\u0006\u0006\u001a\u0004\bZ\u0010[R\u0012\u0010\\\u001a\u00020]X¦\u0004¢\u0006\u0006\u001a\u0004\b^\u0010_R\u001a\u0010`\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010b0aX¦\u0004¢\u0006\u0006\u001a\u0004\bc\u0010dR\u001a\u0010e\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010f0aX¦\u0004¢\u0006\u0006\u001a\u0004\bg\u0010dR\u0018\u0010h\u001a\b\u0012\u0004\u0012\u00020i0aX¦\u0004¢\u0006\u0006\u001a\u0004\bj\u0010dR\u0012\u0010k\u001a\u00020&X¦\u0004¢\u0006\u0006\u001a\u0004\bk\u0010'R\u0012\u0010l\u001a\u00020FX¦\u0004¢\u0006\u0006\u001a\u0004\bm\u0010HR\u0014\u0010n\u001a\u0004\u0018\u00010oX¦\u0004¢\u0006\u0006\u001a\u0004\bp\u0010qR\u0014\u0010r\u001a\u0004\u0018\u00010sX¦\u0004¢\u0006\u0006\u001a\u0004\bt\u0010uR\u0012\u0010v\u001a\u00020wX¦\u0004¢\u0006\u0006\u001a\u0004\bx\u0010yR\u0012\u0010z\u001a\u00020{X¦\u0004¢\u0006\u0006\u001a\u0004\b|\u0010}R#\u0010~\u001a\u0011\u0012\u0004\u0012\u00020\u0013\u0012\u0005\u0012\u00030\u0080\u0001\u0018\u00010\u007fX¦\u0004¢\u0006\b\u001a\u0006\b\u0081\u0001\u0010\u0082\u0001R$\u0010\u0083\u0001\u001a\u0011\u0012\u0004\u0012\u00020\u0013\u0012\u0005\u0012\u00030\u0084\u0001\u0018\u00010\u007fX¦\u0004¢\u0006\b\u001a\u0006\b\u0085\u0001\u0010\u0082\u0001R\u0016\u0010\u0086\u0001\u001a\u00030\u0087\u0001X¦\u0004¢\u0006\b\u001a\u0006\b\u0088\u0001\u0010\u0089\u0001R%\u0010\u008a\u0001\u001a\u0012\u0012\u0005\u0012\u00030\u008c\u0001\u0012\u0004\u0012\u00020F\u0018\u00010\u008b\u0001X¦\u0004¢\u0006\b\u001a\u0006\b\u008d\u0001\u0010\u008e\u0001¨\u0006\u008f\u0001"}, d2 = {"Lcom/facebook/imagepipeline/core/ImagePipelineConfigInterface;", "", "bitmapConfig", "Landroid/graphics/Bitmap$Config;", "getBitmapConfig", "()Landroid/graphics/Bitmap$Config;", "bitmapMemoryCacheParamsSupplier", "Lcom/facebook/common/internal/Supplier;", "Lcom/facebook/imagepipeline/cache/MemoryCacheParams;", "getBitmapMemoryCacheParamsSupplier", "()Lcom/facebook/common/internal/Supplier;", "bitmapMemoryCacheTrimStrategy", "Lcom/facebook/imagepipeline/cache/MemoryCache$CacheTrimStrategy;", "getBitmapMemoryCacheTrimStrategy", "()Lcom/facebook/imagepipeline/cache/MemoryCache$CacheTrimStrategy;", "encodedMemoryCacheTrimStrategy", "getEncodedMemoryCacheTrimStrategy", "bitmapMemoryCacheEntryStateObserver", "Lcom/facebook/imagepipeline/cache/CountingMemoryCache$EntryStateObserver;", "Lcom/facebook/cache/common/CacheKey;", "getBitmapMemoryCacheEntryStateObserver", "()Lcom/facebook/imagepipeline/cache/CountingMemoryCache$EntryStateObserver;", "cacheKeyFactory", "Lcom/facebook/imagepipeline/cache/CacheKeyFactory;", "getCacheKeyFactory", "()Lcom/facebook/imagepipeline/cache/CacheKeyFactory;", "context", "Landroid/content/Context;", "getContext", "()Landroid/content/Context;", "diskCachesStoreSupplier", "Lcom/facebook/imagepipeline/core/DiskCachesStore;", "getDiskCachesStoreSupplier", "downsampleMode", "Lcom/facebook/imagepipeline/core/DownsampleMode;", "getDownsampleMode", "()Lcom/facebook/imagepipeline/core/DownsampleMode;", "isDiskCacheEnabled", "", "()Z", "encodedMemoryCacheParamsSupplier", "getEncodedMemoryCacheParamsSupplier", "executorSupplier", "Lcom/facebook/imagepipeline/core/ExecutorSupplier;", "getExecutorSupplier", "()Lcom/facebook/imagepipeline/core/ExecutorSupplier;", "executorServiceForAnimatedImages", "Lcom/facebook/common/executors/SerialExecutorService;", "getExecutorServiceForAnimatedImages", "()Lcom/facebook/common/executors/SerialExecutorService;", "imageCacheStatsTracker", "Lcom/facebook/imagepipeline/cache/ImageCacheStatsTracker;", "getImageCacheStatsTracker", "()Lcom/facebook/imagepipeline/cache/ImageCacheStatsTracker;", "imageDecoder", "Lcom/facebook/imagepipeline/decoder/ImageDecoder;", "getImageDecoder", "()Lcom/facebook/imagepipeline/decoder/ImageDecoder;", "imageTranscoderFactory", "Lcom/facebook/imagepipeline/transcoder/ImageTranscoderFactory;", "getImageTranscoderFactory", "()Lcom/facebook/imagepipeline/transcoder/ImageTranscoderFactory;", "imageTranscoderType", "", "getImageTranscoderType", "()Ljava/lang/Integer;", "isPrefetchEnabledSupplier", "enableEncodedImageColorSpaceUsage", "getEnableEncodedImageColorSpaceUsage", "mainDiskCacheConfig", "Lcom/facebook/cache/disk/DiskCacheConfig;", "getMainDiskCacheConfig", "()Lcom/facebook/cache/disk/DiskCacheConfig;", "memoryTrimmableRegistry", "Lcom/facebook/common/memory/MemoryTrimmableRegistry;", "getMemoryTrimmableRegistry", "()Lcom/facebook/common/memory/MemoryTrimmableRegistry;", "memoryChunkType", "getMemoryChunkType", "()I", "networkFetcher", "Lcom/facebook/imagepipeline/producers/NetworkFetcher;", "getNetworkFetcher", "()Lcom/facebook/imagepipeline/producers/NetworkFetcher;", "platformBitmapFactory", "Lcom/facebook/imagepipeline/bitmaps/PlatformBitmapFactory;", "getPlatformBitmapFactory", "()Lcom/facebook/imagepipeline/bitmaps/PlatformBitmapFactory;", "poolFactory", "Lcom/facebook/imagepipeline/memory/PoolFactory;", "getPoolFactory", "()Lcom/facebook/imagepipeline/memory/PoolFactory;", "progressiveJpegConfig", "Lcom/facebook/imagepipeline/decoder/ProgressiveJpegConfig;", "getProgressiveJpegConfig", "()Lcom/facebook/imagepipeline/decoder/ProgressiveJpegConfig;", "requestListeners", "", "Lcom/facebook/imagepipeline/listener/RequestListener;", "getRequestListeners", "()Ljava/util/Set;", "requestListener2s", "Lcom/facebook/imagepipeline/listener/RequestListener2;", "getRequestListener2s", "customProducerSequenceFactories", "Lcom/facebook/imagepipeline/producers/CustomProducerSequenceFactory;", "getCustomProducerSequenceFactories", "isResizeAndRotateEnabledForNetwork", "smallImageDiskCacheConfig", "getSmallImageDiskCacheConfig", "imageDecoderConfig", "Lcom/facebook/imagepipeline/decoder/ImageDecoderConfig;", "getImageDecoderConfig", "()Lcom/facebook/imagepipeline/decoder/ImageDecoderConfig;", "callerContextVerifier", "Lcom/facebook/callercontext/CallerContextVerifier;", "getCallerContextVerifier", "()Lcom/facebook/callercontext/CallerContextVerifier;", "experiments", "Lcom/facebook/imagepipeline/core/ImagePipelineExperiments;", "getExperiments", "()Lcom/facebook/imagepipeline/core/ImagePipelineExperiments;", "closeableReferenceLeakTracker", "Lcom/facebook/imagepipeline/debug/CloseableReferenceLeakTracker;", "getCloseableReferenceLeakTracker", "()Lcom/facebook/imagepipeline/debug/CloseableReferenceLeakTracker;", "bitmapCacheOverride", "Lcom/facebook/imagepipeline/cache/MemoryCache;", "Lcom/facebook/imagepipeline/image/CloseableImage;", "getBitmapCacheOverride", "()Lcom/facebook/imagepipeline/cache/MemoryCache;", "encodedMemoryCacheOverride", "Lcom/facebook/common/memory/PooledByteBuffer;", "getEncodedMemoryCacheOverride", "bitmapMemoryCacheFactory", "Lcom/facebook/imagepipeline/cache/BitmapMemoryCacheFactory;", "getBitmapMemoryCacheFactory", "()Lcom/facebook/imagepipeline/cache/BitmapMemoryCacheFactory;", "dynamicDiskCacheConfigMap", "", "", "getDynamicDiskCacheConfigMap", "()Ljava/util/Map;", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface ImagePipelineConfigInterface {
    MemoryCache<CacheKey, CloseableImage> getBitmapCacheOverride();

    Bitmap.Config getBitmapConfig();

    CountingMemoryCache.EntryStateObserver<CacheKey> getBitmapMemoryCacheEntryStateObserver();

    BitmapMemoryCacheFactory getBitmapMemoryCacheFactory();

    Supplier<MemoryCacheParams> getBitmapMemoryCacheParamsSupplier();

    MemoryCache.CacheTrimStrategy getBitmapMemoryCacheTrimStrategy();

    CacheKeyFactory getCacheKeyFactory();

    CallerContextVerifier getCallerContextVerifier();

    CloseableReferenceLeakTracker getCloseableReferenceLeakTracker();

    Context getContext();

    Set<CustomProducerSequenceFactory> getCustomProducerSequenceFactories();

    Supplier<DiskCachesStore> getDiskCachesStoreSupplier();

    DownsampleMode getDownsampleMode();

    Map<String, DiskCacheConfig> getDynamicDiskCacheConfigMap();

    Supplier<Boolean> getEnableEncodedImageColorSpaceUsage();

    MemoryCache<CacheKey, PooledByteBuffer> getEncodedMemoryCacheOverride();

    Supplier<MemoryCacheParams> getEncodedMemoryCacheParamsSupplier();

    MemoryCache.CacheTrimStrategy getEncodedMemoryCacheTrimStrategy();

    SerialExecutorService getExecutorServiceForAnimatedImages();

    ExecutorSupplier getExecutorSupplier();

    ImagePipelineExperiments getExperiments();

    ImageCacheStatsTracker getImageCacheStatsTracker();

    ImageDecoder getImageDecoder();

    ImageDecoderConfig getImageDecoderConfig();

    ImageTranscoderFactory getImageTranscoderFactory();

    Integer getImageTranscoderType();

    DiskCacheConfig getMainDiskCacheConfig();

    int getMemoryChunkType();

    MemoryTrimmableRegistry getMemoryTrimmableRegistry();

    NetworkFetcher<?> getNetworkFetcher();

    PlatformBitmapFactory getPlatformBitmapFactory();

    PoolFactory getPoolFactory();

    ProgressiveJpegConfig getProgressiveJpegConfig();

    Set<RequestListener2> getRequestListener2s();

    Set<RequestListener> getRequestListeners();

    DiskCacheConfig getSmallImageDiskCacheConfig();

    /* renamed from: isDiskCacheEnabled */
    boolean getIsDiskCacheEnabled();

    Supplier<Boolean> isPrefetchEnabledSupplier();

    /* renamed from: isResizeAndRotateEnabledForNetwork */
    boolean getIsResizeAndRotateEnabledForNetwork();
}
