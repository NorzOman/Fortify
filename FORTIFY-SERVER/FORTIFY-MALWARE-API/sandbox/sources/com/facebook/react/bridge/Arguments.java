package com.facebook.react.bridge;

import android.os.Bundle;
import android.os.Parcelable;
import java.lang.reflect.Array;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes.dex */
public class Arguments {
    private static Object makeNativeObject(Object obj) {
        if (obj == null) {
            return null;
        }
        if ((obj instanceof Float) || (obj instanceof Long) || (obj instanceof Byte) || (obj instanceof Short)) {
            return Double.valueOf(((Number) obj).doubleValue());
        }
        if (obj.getClass().isArray()) {
            return makeNativeArray(obj);
        }
        if (obj instanceof List) {
            return makeNativeArray((List) obj);
        }
        if (obj instanceof Map) {
            return makeNativeMap((Map<String, Object>) obj);
        }
        if (obj instanceof Bundle) {
            return makeNativeMap((Bundle) obj);
        }
        if (obj instanceof JavaOnlyMap) {
            return makeNativeMap(((JavaOnlyMap) obj).toHashMap());
        }
        return obj instanceof JavaOnlyArray ? makeNativeArray((List) ((JavaOnlyArray) obj).toArrayList()) : obj;
    }

    public static WritableNativeArray makeNativeArray(List list) {
        WritableNativeArray writableNativeArray = new WritableNativeArray();
        if (list == null) {
            return writableNativeArray;
        }
        Iterator it = list.iterator();
        while (it.hasNext()) {
            Object objMakeNativeObject = makeNativeObject(it.next());
            if (objMakeNativeObject == null) {
                writableNativeArray.pushNull();
            } else if (objMakeNativeObject instanceof Boolean) {
                writableNativeArray.pushBoolean(((Boolean) objMakeNativeObject).booleanValue());
            } else if (objMakeNativeObject instanceof Integer) {
                writableNativeArray.pushInt(((Integer) objMakeNativeObject).intValue());
            } else if (objMakeNativeObject instanceof Double) {
                writableNativeArray.pushDouble(((Double) objMakeNativeObject).doubleValue());
            } else if (objMakeNativeObject instanceof String) {
                writableNativeArray.pushString((String) objMakeNativeObject);
            } else if (objMakeNativeObject instanceof WritableNativeArray) {
                writableNativeArray.pushArray((WritableNativeArray) objMakeNativeObject);
            } else if (objMakeNativeObject instanceof WritableNativeMap) {
                writableNativeArray.pushMap((WritableNativeMap) objMakeNativeObject);
            } else {
                throw new IllegalArgumentException("Could not convert " + objMakeNativeObject.getClass());
            }
        }
        return writableNativeArray;
    }

    public static <T> WritableNativeArray makeNativeArray(final Object obj) {
        if (obj == null) {
            return new WritableNativeArray();
        }
        return makeNativeArray((List) new AbstractList() { // from class: com.facebook.react.bridge.Arguments.1
            @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
            public int size() {
                return Array.getLength(obj);
            }

            @Override // java.util.AbstractList, java.util.List
            public Object get(int i) {
                return Array.get(obj, i);
            }
        });
    }

    private static void addEntry(WritableNativeMap writableNativeMap, String str, Object obj) {
        Object objMakeNativeObject = makeNativeObject(obj);
        if (objMakeNativeObject == null) {
            writableNativeMap.putNull(str);
            return;
        }
        if (objMakeNativeObject instanceof Boolean) {
            writableNativeMap.putBoolean(str, ((Boolean) objMakeNativeObject).booleanValue());
            return;
        }
        if (objMakeNativeObject instanceof Integer) {
            writableNativeMap.putInt(str, ((Integer) objMakeNativeObject).intValue());
            return;
        }
        if (objMakeNativeObject instanceof Number) {
            writableNativeMap.putDouble(str, ((Number) objMakeNativeObject).doubleValue());
            return;
        }
        if (objMakeNativeObject instanceof String) {
            writableNativeMap.putString(str, (String) objMakeNativeObject);
        } else if (objMakeNativeObject instanceof WritableNativeArray) {
            writableNativeMap.putArray(str, (WritableNativeArray) objMakeNativeObject);
        } else {
            if (objMakeNativeObject instanceof WritableNativeMap) {
                writableNativeMap.putMap(str, (WritableNativeMap) objMakeNativeObject);
                return;
            }
            throw new IllegalArgumentException("Could not convert " + objMakeNativeObject.getClass());
        }
    }

    public static WritableNativeMap makeNativeMap(Map<String, Object> map) {
        WritableNativeMap writableNativeMap = new WritableNativeMap();
        if (map == null) {
            return writableNativeMap;
        }
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            addEntry(writableNativeMap, entry.getKey(), entry.getValue());
        }
        return writableNativeMap;
    }

    public static WritableNativeMap makeNativeMap(Bundle bundle) {
        WritableNativeMap writableNativeMap = new WritableNativeMap();
        if (bundle == null) {
            return writableNativeMap;
        }
        for (String str : bundle.keySet()) {
            addEntry(writableNativeMap, str, bundle.get(str));
        }
        return writableNativeMap;
    }

    public static WritableArray createArray() {
        return new WritableNativeArray();
    }

    public static WritableMap createMap() {
        return new WritableNativeMap();
    }

    public static WritableNativeArray fromJavaArgs(Object[] objArr) {
        WritableNativeArray writableNativeArray = new WritableNativeArray();
        for (Object obj : objArr) {
            if (obj == null) {
                writableNativeArray.pushNull();
            } else {
                Class<?> cls = obj.getClass();
                if (cls == Boolean.class) {
                    writableNativeArray.pushBoolean(((Boolean) obj).booleanValue());
                } else if (cls == Integer.class) {
                    writableNativeArray.pushDouble(((Integer) obj).doubleValue());
                } else if (cls == Double.class) {
                    writableNativeArray.pushDouble(((Double) obj).doubleValue());
                } else if (cls == Float.class) {
                    writableNativeArray.pushDouble(((Float) obj).doubleValue());
                } else if (cls == String.class) {
                    writableNativeArray.pushString(obj.toString());
                } else if (cls == WritableNativeMap.class) {
                    writableNativeArray.pushMap((WritableNativeMap) obj);
                } else if (cls == WritableNativeArray.class) {
                    writableNativeArray.pushArray((WritableNativeArray) obj);
                } else {
                    throw new RuntimeException("Cannot convert argument of type " + cls);
                }
            }
        }
        return writableNativeArray;
    }

    public static WritableArray fromArray(Object obj) {
        WritableArray writableArrayCreateArray = createArray();
        int i = 0;
        if (obj instanceof String[]) {
            String[] strArr = (String[]) obj;
            int length = strArr.length;
            while (i < length) {
                writableArrayCreateArray.pushString(strArr[i]);
                i++;
            }
        } else if (obj instanceof Bundle[]) {
            Bundle[] bundleArr = (Bundle[]) obj;
            int length2 = bundleArr.length;
            while (i < length2) {
                writableArrayCreateArray.pushMap(fromBundle(bundleArr[i]));
                i++;
            }
        } else if (obj instanceof int[]) {
            int[] iArr = (int[]) obj;
            int length3 = iArr.length;
            while (i < length3) {
                writableArrayCreateArray.pushInt(iArr[i]);
                i++;
            }
        } else if (obj instanceof float[]) {
            int length4 = ((float[]) obj).length;
            while (i < length4) {
                writableArrayCreateArray.pushDouble(r5[i]);
                i++;
            }
        } else if (obj instanceof double[]) {
            double[] dArr = (double[]) obj;
            int length5 = dArr.length;
            while (i < length5) {
                writableArrayCreateArray.pushDouble(dArr[i]);
                i++;
            }
        } else if (obj instanceof boolean[]) {
            boolean[] zArr = (boolean[]) obj;
            int length6 = zArr.length;
            while (i < length6) {
                writableArrayCreateArray.pushBoolean(zArr[i]);
                i++;
            }
        } else if (obj instanceof Parcelable[]) {
            Parcelable[] parcelableArr = (Parcelable[]) obj;
            int length7 = parcelableArr.length;
            while (i < length7) {
                Parcelable parcelable = parcelableArr[i];
                if (parcelable instanceof Bundle) {
                    writableArrayCreateArray.pushMap(fromBundle((Bundle) parcelable));
                    i++;
                } else {
                    throw new IllegalArgumentException("Unexpected array member type " + parcelable.getClass());
                }
            }
        } else {
            throw new IllegalArgumentException("Unknown array type " + obj.getClass());
        }
        return writableArrayCreateArray;
    }

    public static WritableArray fromList(List list) {
        WritableArray writableArrayCreateArray = createArray();
        for (Object obj : list) {
            if (obj == null) {
                writableArrayCreateArray.pushNull();
            } else if (obj.getClass().isArray()) {
                writableArrayCreateArray.pushArray(fromArray(obj));
            } else if (obj instanceof Bundle) {
                writableArrayCreateArray.pushMap(fromBundle((Bundle) obj));
            } else if (obj instanceof List) {
                writableArrayCreateArray.pushArray(fromList((List) obj));
            } else if (obj instanceof String) {
                writableArrayCreateArray.pushString((String) obj);
            } else if (obj instanceof Integer) {
                writableArrayCreateArray.pushInt(((Integer) obj).intValue());
            } else if (obj instanceof Number) {
                writableArrayCreateArray.pushDouble(((Number) obj).doubleValue());
            } else if (obj instanceof Boolean) {
                writableArrayCreateArray.pushBoolean(((Boolean) obj).booleanValue());
            } else {
                throw new IllegalArgumentException("Unknown value type " + obj.getClass());
            }
        }
        return writableArrayCreateArray;
    }

    public static WritableMap fromBundle(Bundle bundle) {
        WritableMap writableMapCreateMap = createMap();
        for (String str : bundle.keySet()) {
            Object obj = bundle.get(str);
            if (obj == null) {
                writableMapCreateMap.putNull(str);
            } else if (obj.getClass().isArray()) {
                writableMapCreateMap.putArray(str, fromArray(obj));
            } else if (obj instanceof String) {
                writableMapCreateMap.putString(str, (String) obj);
            } else if (obj instanceof Number) {
                if (obj instanceof Integer) {
                    writableMapCreateMap.putInt(str, ((Integer) obj).intValue());
                } else {
                    writableMapCreateMap.putDouble(str, ((Number) obj).doubleValue());
                }
            } else if (obj instanceof Boolean) {
                writableMapCreateMap.putBoolean(str, ((Boolean) obj).booleanValue());
            } else if (obj instanceof Bundle) {
                writableMapCreateMap.putMap(str, fromBundle((Bundle) obj));
            } else if (obj instanceof List) {
                writableMapCreateMap.putArray(str, fromList((List) obj));
            } else {
                throw new IllegalArgumentException("Could not convert " + obj.getClass());
            }
        }
        return writableMapCreateMap;
    }

    public static ArrayList toList(ReadableArray readableArray) {
        if (readableArray == null) {
            return null;
        }
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < readableArray.size(); i++) {
            switch (AnonymousClass2.$SwitchMap$com$facebook$react$bridge$ReadableType[readableArray.getType(i).ordinal()]) {
                case 1:
                    arrayList.add(null);
                    break;
                case 2:
                    arrayList.add(Boolean.valueOf(readableArray.getBoolean(i)));
                    break;
                case 3:
                    double d = readableArray.getDouble(i);
                    if (d == Math.rint(d)) {
                        arrayList.add(Integer.valueOf((int) d));
                        break;
                    } else {
                        arrayList.add(Double.valueOf(d));
                        break;
                    }
                case 4:
                    arrayList.add(readableArray.getString(i));
                    break;
                case 5:
                    arrayList.add(toBundle(readableArray.getMap(i)));
                    break;
                case 6:
                    arrayList.add(toList(readableArray.getArray(i)));
                    break;
                default:
                    throw new IllegalArgumentException("Could not convert object in array.");
            }
        }
        return arrayList;
    }

    /* renamed from: com.facebook.react.bridge.Arguments$2, reason: invalid class name */
    static /* synthetic */ class AnonymousClass2 {
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

    public static Bundle toBundle(ReadableMap readableMap) {
        if (readableMap == null) {
            return null;
        }
        ReadableMapKeySetIterator readableMapKeySetIteratorKeySetIterator = readableMap.keySetIterator();
        Bundle bundle = new Bundle();
        while (readableMapKeySetIteratorKeySetIterator.hasNextKey()) {
            String strNextKey = readableMapKeySetIteratorKeySetIterator.nextKey();
            switch (AnonymousClass2.$SwitchMap$com$facebook$react$bridge$ReadableType[readableMap.getType(strNextKey).ordinal()]) {
                case 1:
                    bundle.putString(strNextKey, null);
                    break;
                case 2:
                    bundle.putBoolean(strNextKey, readableMap.getBoolean(strNextKey));
                    break;
                case 3:
                    bundle.putDouble(strNextKey, readableMap.getDouble(strNextKey));
                    break;
                case 4:
                    bundle.putString(strNextKey, readableMap.getString(strNextKey));
                    break;
                case 5:
                    bundle.putBundle(strNextKey, toBundle(readableMap.getMap(strNextKey)));
                    break;
                case 6:
                    bundle.putSerializable(strNextKey, toList(readableMap.getArray(strNextKey)));
                    break;
                default:
                    throw new IllegalArgumentException("Could not convert object with key: " + strNextKey + ".");
            }
        }
        return bundle;
    }
}
