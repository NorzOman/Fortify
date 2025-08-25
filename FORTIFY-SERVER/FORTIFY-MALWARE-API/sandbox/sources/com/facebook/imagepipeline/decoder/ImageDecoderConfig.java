package com.facebook.imagepipeline.decoder;

import com.facebook.imageformat.ImageFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class ImageDecoderConfig {

    @Nullable
    private final Map<ImageFormat, ImageDecoder> mCustomImageDecoders;

    @Nullable
    private final List<ImageFormat.FormatChecker> mCustomImageFormats;

    private ImageDecoderConfig(Builder builder) {
        this.mCustomImageDecoders = builder.mCustomImageDecoders;
        this.mCustomImageFormats = builder.mCustomImageFormats;
    }

    @Nullable
    public Map<ImageFormat, ImageDecoder> getCustomImageDecoders() {
        return this.mCustomImageDecoders;
    }

    @Nullable
    public List<ImageFormat.FormatChecker> getCustomImageFormats() {
        return this.mCustomImageFormats;
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public static final class Builder {

        @Nullable
        private Map<ImageFormat, ImageDecoder> mCustomImageDecoders;

        @Nullable
        private List<ImageFormat.FormatChecker> mCustomImageFormats;

        public Builder addDecodingCapability(ImageFormat imageFormat, ImageFormat.FormatChecker formatChecker, @Nullable ImageDecoder imageDecoder) {
            if (this.mCustomImageFormats == null) {
                this.mCustomImageFormats = new ArrayList();
            }
            this.mCustomImageFormats.add(formatChecker);
            if (imageDecoder != null) {
                overrideDecoder(imageFormat, imageDecoder);
            }
            return this;
        }

        public Builder overrideDecoder(ImageFormat imageFormat, ImageDecoder imageDecoder) {
            if (this.mCustomImageDecoders == null) {
                this.mCustomImageDecoders = new HashMap();
            }
            this.mCustomImageDecoders.put(imageFormat, imageDecoder);
            return this;
        }

        public ImageDecoderConfig build() {
            return new ImageDecoderConfig(this);
        }
    }
}
