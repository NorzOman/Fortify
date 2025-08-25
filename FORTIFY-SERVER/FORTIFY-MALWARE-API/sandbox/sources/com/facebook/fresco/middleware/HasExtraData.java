package com.facebook.fresco.middleware;

import java.util.Map;
import kotlin.Metadata;

/* compiled from: HasExtraData.kt */
@Metadata(d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\u0010$\n\u0002\b\u0006\bf\u0018\u0000 \u00142\u00020\u0001:\u0001\u0014J%\u0010\u0002\u001a\u00020\u0003\"\u0004\b\u0000\u0010\u00042\u0006\u0010\u0005\u001a\u00020\u00062\b\u0010\u0007\u001a\u0004\u0018\u0001H\u0004H&¢\u0006\u0002\u0010\bJ\u001d\u0010\t\u001a\u0004\u0018\u0001H\u0004\"\u0004\b\u0000\u0010\u00042\u0006\u0010\u0005\u001a\u00020\u0006H&¢\u0006\u0002\u0010\nJ)\u0010\t\u001a\u0004\u0018\u0001H\u0004\"\u0004\b\u0000\u0010\u00042\u0006\u0010\u0005\u001a\u00020\u00062\n\b\u0002\u0010\u000b\u001a\u0004\u0018\u0001H\u0004H&¢\u0006\u0002\u0010\fJ\u001d\u0010\r\u001a\u0012\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u00010\u000fj\u0002`\u000eH&¢\u0006\u0002\u0010\u0010J%\u0010\u0011\u001a\u00020\u00032\u0016\u0010\u0012\u001a\u0012\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u00010\u000fj\u0002`\u000eH&¢\u0006\u0002\u0010\u0013¨\u0006\u0015"}, d2 = {"Lcom/facebook/fresco/middleware/HasExtraData;", "", "putExtra", "", "E", "key", "", "value", "(Ljava/lang/String;Ljava/lang/Object;)V", "getExtra", "(Ljava/lang/String;)Ljava/lang/Object;", "valueIfNotFound", "(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;", "getExtras", "Lcom/facebook/fresco/middleware/Extras;", "", "()Ljava/util/Map;", "putExtras", "extras", "(Ljava/util/Map;)V", "Companion", "middleware_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface HasExtraData {

    /* renamed from: Companion, reason: from kotlin metadata */
    public static final Companion INSTANCE = Companion.$$INSTANCE;
    public static final String KEY_BITMAP_CONFIG = "bitmap_config";
    public static final String KEY_COLOR_SPACE = "image_color_space";
    public static final String KEY_ENCODED_HEIGHT = "encoded_height";
    public static final String KEY_ENCODED_SIZE = "encoded_size";
    public static final String KEY_ENCODED_WIDTH = "encoded_width";
    public static final String KEY_ID = "id";
    public static final String KEY_IMAGE_FORMAT = "image_format";
    public static final String KEY_IMAGE_SOURCE_EXTRAS = "image_source_extras";
    public static final String KEY_IMAGE_SOURCE_TYPE = "image_source_type";
    public static final String KEY_IS_ROUNDED = "is_rounded";
    public static final String KEY_LAST_SCAN_NUMBER = "last_scan_num";
    public static final String KEY_MODIFIED_URL = "modified_url";
    public static final String KEY_MULTIPLEX_BITMAP_COUNT = "multiplex_bmp_cnt";
    public static final String KEY_MULTIPLEX_ENCODED_COUNT = "multiplex_enc_cnt";
    public static final String KEY_NON_FATAL_DECODE_ERROR = "non_fatal_decode_error";
    public static final String KEY_ORIGIN = "origin";
    public static final String KEY_ORIGINAL_URL = "original_url";
    public static final String KEY_ORIGIN_SUBCATEGORY = "origin_sub";
    public static final String KEY_URI_SOURCE = "uri_source";

    <E> E getExtra(String key);

    <E> E getExtra(String key, E valueIfNotFound);

    Map<String, Object> getExtras();

    <E> void putExtra(String key, E value);

    void putExtras(Map<String, ? extends Object> extras);

    /* compiled from: HasExtraData.kt */
    @Metadata(k = 3, mv = {2, 0, 0}, xi = 48)
    public static final class DefaultImpls {
        public static /* synthetic */ Object getExtra$default(HasExtraData hasExtraData, String str, Object obj, int i, Object obj2) {
            if (obj2 != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: getExtra");
            }
            if ((i & 2) != 0) {
                obj = null;
            }
            return hasExtraData.getExtra(str, obj);
        }
    }

    /* compiled from: HasExtraData.kt */
    @Metadata(d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0013\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003R\u000e\u0010\u0004\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u0007\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\b\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\t\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\n\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u000b\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\f\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\r\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u000e\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u000f\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u0010\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u0011\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u0012\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u0013\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u0014\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u0015\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u0016\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u0017\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000¨\u0006\u0018"}, d2 = {"Lcom/facebook/fresco/middleware/HasExtraData$Companion;", "", "<init>", "()V", "KEY_ID", "", "KEY_ENCODED_SIZE", "KEY_ENCODED_WIDTH", "KEY_ENCODED_HEIGHT", "KEY_URI_SOURCE", "KEY_IMAGE_FORMAT", "KEY_BITMAP_CONFIG", "KEY_IS_ROUNDED", "KEY_NON_FATAL_DECODE_ERROR", "KEY_ORIGINAL_URL", "KEY_MODIFIED_URL", "KEY_IMAGE_SOURCE_TYPE", "KEY_ORIGIN", "KEY_ORIGIN_SUBCATEGORY", "KEY_MULTIPLEX_BITMAP_COUNT", "KEY_MULTIPLEX_ENCODED_COUNT", "KEY_LAST_SCAN_NUMBER", "KEY_IMAGE_SOURCE_EXTRAS", "KEY_COLOR_SPACE", "middleware_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class Companion {
        static final /* synthetic */ Companion $$INSTANCE = new Companion();
        public static final String KEY_BITMAP_CONFIG = "bitmap_config";
        public static final String KEY_COLOR_SPACE = "image_color_space";
        public static final String KEY_ENCODED_HEIGHT = "encoded_height";
        public static final String KEY_ENCODED_SIZE = "encoded_size";
        public static final String KEY_ENCODED_WIDTH = "encoded_width";
        public static final String KEY_ID = "id";
        public static final String KEY_IMAGE_FORMAT = "image_format";
        public static final String KEY_IMAGE_SOURCE_EXTRAS = "image_source_extras";
        public static final String KEY_IMAGE_SOURCE_TYPE = "image_source_type";
        public static final String KEY_IS_ROUNDED = "is_rounded";
        public static final String KEY_LAST_SCAN_NUMBER = "last_scan_num";
        public static final String KEY_MODIFIED_URL = "modified_url";
        public static final String KEY_MULTIPLEX_BITMAP_COUNT = "multiplex_bmp_cnt";
        public static final String KEY_MULTIPLEX_ENCODED_COUNT = "multiplex_enc_cnt";
        public static final String KEY_NON_FATAL_DECODE_ERROR = "non_fatal_decode_error";
        public static final String KEY_ORIGIN = "origin";
        public static final String KEY_ORIGINAL_URL = "original_url";
        public static final String KEY_ORIGIN_SUBCATEGORY = "origin_sub";
        public static final String KEY_URI_SOURCE = "uri_source";

        private Companion() {
        }
    }
}
