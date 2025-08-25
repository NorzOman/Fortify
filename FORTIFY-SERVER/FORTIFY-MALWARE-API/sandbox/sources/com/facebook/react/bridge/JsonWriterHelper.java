package com.facebook.react.bridge;

import android.util.JsonWriter;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes.dex */
public class JsonWriterHelper {
    public static void value(JsonWriter jsonWriter, Object obj) throws IOException {
        if (obj instanceof Map) {
            mapValue(jsonWriter, (Map) obj);
            return;
        }
        if (obj instanceof List) {
            listValue(jsonWriter, (List) obj);
            return;
        }
        if (obj instanceof ReadableMap) {
            readableMapValue(jsonWriter, (ReadableMap) obj);
            return;
        }
        if (obj instanceof ReadableArray) {
            readableArrayValue(jsonWriter, (ReadableArray) obj);
        } else if (obj instanceof Dynamic) {
            dynamicValue(jsonWriter, (Dynamic) obj);
        } else {
            objectValue(jsonWriter, obj);
        }
    }

    /* renamed from: com.facebook.react.bridge.JsonWriterHelper$1, reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$facebook$react$bridge$ReadableType;

        static {
            int[] iArr = new int[ReadableType.values().length];
            $SwitchMap$com$facebook$react$bridge$ReadableType = iArr;
            try {
                iArr[ReadableType.Null.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$facebook$react$bridge$ReadableType[ReadableType.Boolean.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$facebook$react$bridge$ReadableType[ReadableType.Number.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$com$facebook$react$bridge$ReadableType[ReadableType.String.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                $SwitchMap$com$facebook$react$bridge$ReadableType[ReadableType.Map.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                $SwitchMap$com$facebook$react$bridge$ReadableType[ReadableType.Array.ordinal()] = 6;
            } catch (NoSuchFieldError unused6) {
            }
        }
    }

    private static void dynamicValue(JsonWriter jsonWriter, Dynamic dynamic) throws IOException {
        switch (AnonymousClass1.$SwitchMap$com$facebook$react$bridge$ReadableType[dynamic.getType().ordinal()]) {
            case 1:
                jsonWriter.nullValue();
                return;
            case 2:
                jsonWriter.value(dynamic.asBoolean());
                return;
            case 3:
                jsonWriter.value(dynamic.asDouble());
                return;
            case 4:
                jsonWriter.value(dynamic.asString());
                return;
            case 5:
                readableMapValue(jsonWriter, dynamic.asMap());
                return;
            case 6:
                readableArrayValue(jsonWriter, dynamic.asArray());
                return;
            default:
                throw new IllegalArgumentException("Unknown data type: " + dynamic.getType());
        }
    }

    private static void readableMapValue(JsonWriter jsonWriter, ReadableMap readableMap) throws IOException {
        ReadableMapKeySetIterator readableMapKeySetIteratorKeySetIterator;
        jsonWriter.beginObject();
        try {
            readableMapKeySetIteratorKeySetIterator = readableMap.keySetIterator();
        } finally {
            jsonWriter.endObject();
        }
        while (readableMapKeySetIteratorKeySetIterator.hasNextKey()) {
            String strNextKey = readableMapKeySetIteratorKeySetIterator.nextKey();
            jsonWriter.name(strNextKey);
            switch (AnonymousClass1.$SwitchMap$com$facebook$react$bridge$ReadableType[readableMap.getType(strNextKey).ordinal()]) {
                case 1:
                    jsonWriter.nullValue();
                    continue;
                case 2:
                    jsonWriter.value(readableMap.getBoolean(strNextKey));
                    continue;
                case 3:
                    jsonWriter.value(readableMap.getDouble(strNextKey));
                    continue;
                case 4:
                    jsonWriter.value(readableMap.getString(strNextKey));
                    continue;
                case 5:
                    readableMapValue(jsonWriter, readableMap.getMap(strNextKey));
                    continue;
                case 6:
                    readableArrayValue(jsonWriter, readableMap.getArray(strNextKey));
                    continue;
                default:
                    throw new IllegalArgumentException("Unknown data type: " + readableMap.getType(strNextKey));
            }
            jsonWriter.endObject();
        }
    }

    public static void readableArrayValue(JsonWriter jsonWriter, ReadableArray readableArray) throws IOException {
        jsonWriter.beginArray();
        for (int i = 0; i < readableArray.size(); i++) {
            try {
                switch (AnonymousClass1.$SwitchMap$com$facebook$react$bridge$ReadableType[readableArray.getType(i).ordinal()]) {
                    case 1:
                        jsonWriter.nullValue();
                        continue;
                    case 2:
                        jsonWriter.value(readableArray.getBoolean(i));
                        continue;
                    case 3:
                        jsonWriter.value(readableArray.getDouble(i));
                        continue;
                    case 4:
                        jsonWriter.value(readableArray.getString(i));
                        continue;
                    case 5:
                        readableMapValue(jsonWriter, readableArray.getMap(i));
                        continue;
                    case 6:
                        readableArrayValue(jsonWriter, readableArray.getArray(i));
                        continue;
                    default:
                        throw new IllegalArgumentException("Unknown data type: " + readableArray.getType(i));
                }
            } finally {
                jsonWriter.endArray();
            }
            jsonWriter.endArray();
        }
    }

    private static void mapValue(JsonWriter jsonWriter, Map<?, ?> map) throws IOException {
        jsonWriter.beginObject();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            jsonWriter.name(entry.getKey().toString());
            value(jsonWriter, entry.getValue());
        }
        jsonWriter.endObject();
    }

    private static void listValue(JsonWriter jsonWriter, List<?> list) throws IOException {
        jsonWriter.beginArray();
        Iterator<?> it = list.iterator();
        while (it.hasNext()) {
            objectValue(jsonWriter, it.next());
        }
        jsonWriter.endArray();
    }

    private static void objectValue(JsonWriter jsonWriter, Object obj) throws IOException {
        if (obj == null) {
            jsonWriter.nullValue();
            return;
        }
        if (obj instanceof String) {
            jsonWriter.value((String) obj);
        } else if (obj instanceof Number) {
            jsonWriter.value((Number) obj);
        } else {
            if (obj instanceof Boolean) {
                jsonWriter.value(((Boolean) obj).booleanValue());
                return;
            }
            throw new IllegalArgumentException("Unknown value: " + obj);
        }
    }
}
