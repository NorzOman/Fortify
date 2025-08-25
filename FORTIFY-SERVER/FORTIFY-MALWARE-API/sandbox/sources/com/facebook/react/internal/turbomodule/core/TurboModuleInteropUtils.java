package com.facebook.react.internal.turbomodule.core;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.Dynamic;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.turbomodule.core.interfaces.TurboModule;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/* loaded from: classes.dex */
class TurboModuleInteropUtils {
    TurboModuleInteropUtils() {
    }

    static class MethodDescriptor {
        public final String jniSignature;
        public final int jsArgCount;
        public final String jsiReturnKind;
        public final String methodName;

        MethodDescriptor(String str, String str2, String str3, int i) {
            this.methodName = str;
            this.jniSignature = str2;
            this.jsiReturnKind = str3;
            this.jsArgCount = i;
        }
    }

    private static class ParsingException extends RuntimeException {
        ParsingException(String str, String str2) {
            super("Unable to parse @ReactMethod annotations from native module: " + str + ". Details: " + str2);
        }

        ParsingException(String str, String str2, String str3) {
            super("Unable to parse @ReactMethod annotation from native module method: " + str + "." + str2 + "(). Details: " + str3);
        }
    }

    static List<MethodDescriptor> getMethodDescriptorsFromModule(NativeModule nativeModule) {
        Method[] methodsFromModule = getMethodsFromModule(nativeModule);
        ArrayList arrayList = new ArrayList();
        HashSet hashSet = new HashSet();
        for (Method method : methodsFromModule) {
            ReactMethod reactMethod = (ReactMethod) method.getAnnotation(ReactMethod.class);
            String name = nativeModule.getName();
            String name2 = method.getName();
            if (reactMethod != null || "getConstants".equals(name2)) {
                if (hashSet.contains(name2)) {
                    throw new ParsingException(name, "Module exports two methods to JavaScript with the same name: \"" + name2);
                }
                hashSet.add(name2);
                Class<?>[] parameterTypes = method.getParameterTypes();
                Class<?> returnType = method.getReturnType();
                if (!"getConstants".equals(name2) && ((!reactMethod.isBlockingSynchronousMethod() || returnType != Void.TYPE) && !reactMethod.isBlockingSynchronousMethod())) {
                    Class cls = Void.TYPE;
                }
                arrayList.add(new MethodDescriptor(name2, createJniSignature(name, name2, parameterTypes, returnType), createJSIReturnKind(name, name2, parameterTypes, returnType), getJsArgCount(name, name2, parameterTypes)));
            }
        }
        return arrayList;
    }

    private static Method[] getMethodsFromModule(NativeModule nativeModule) {
        Class<?> cls = nativeModule.getClass();
        Class<? super Object> superclass = cls.getSuperclass();
        if (TurboModule.class.isAssignableFrom(superclass)) {
            cls = superclass;
        }
        return cls.getDeclaredMethods();
    }

    private static String createJniSignature(String str, String str2, Class<?>[] clsArr, Class<?> cls) {
        StringBuilder sb = new StringBuilder("(");
        for (Class<?> cls2 : clsArr) {
            sb.append(convertParamClassToJniType(str, str2, cls2));
        }
        sb.append(")");
        sb.append(convertReturnClassToJniType(str, str2, cls));
        return sb.toString();
    }

    private static String convertParamClassToJniType(String str, String str2, Class<?> cls) {
        if (cls == Boolean.TYPE) {
            return "Z";
        }
        if (cls == Integer.TYPE) {
            return "I";
        }
        if (cls == Double.TYPE) {
            return "D";
        }
        if (cls == Float.TYPE) {
            return "F";
        }
        if (cls == Boolean.class || cls == Integer.class || cls == Double.class || cls == Float.class || cls == String.class || cls == Callback.class || cls == Promise.class || cls == ReadableMap.class || cls == ReadableArray.class || cls == Dynamic.class) {
            return convertClassToJniType(cls);
        }
        throw new ParsingException(str, str2, "Unable to parse JNI signature. Detected unsupported parameter class: " + cls.getCanonicalName());
    }

    private static String convertReturnClassToJniType(String str, String str2, Class<?> cls) {
        if (cls == Boolean.TYPE) {
            return "Z";
        }
        if (cls == Integer.TYPE) {
            return "I";
        }
        if (cls == Double.TYPE) {
            return "D";
        }
        if (cls == Float.TYPE) {
            return "F";
        }
        if (cls == Void.TYPE) {
            return "V";
        }
        if (cls == Boolean.class || cls == Integer.class || cls == Double.class || cls == Float.class || cls == String.class || cls == WritableMap.class || cls == WritableArray.class || cls == Map.class) {
            return convertClassToJniType(cls);
        }
        throw new ParsingException(str, str2, "Unable to parse JNI signature. Detected unsupported return class: " + cls.getCanonicalName());
    }

    private static String convertClassToJniType(Class<?> cls) {
        return "L" + cls.getCanonicalName().replace('.', '/') + ';';
    }

    private static int getJsArgCount(String str, String str2, Class<?>[] clsArr) {
        for (int i = 0; i < clsArr.length; i++) {
            if (clsArr[i] == Promise.class) {
                if (i != clsArr.length - 1) {
                    throw new ParsingException(str, str2, "Unable to parse JavaScript arg count. Promises must be used as last parameter only.");
                }
                return clsArr.length - 1;
            }
        }
        return clsArr.length;
    }

    private static String createJSIReturnKind(String str, String str2, Class<?>[] clsArr, Class<?> cls) {
        for (int i = 0; i < clsArr.length; i++) {
            if (clsArr[i] == Promise.class) {
                if (i != clsArr.length - 1) {
                    throw new ParsingException(str, str2, "Unable to parse JSI return kind. Promises must be used as last parameter only.");
                }
                return "PromiseKind";
            }
        }
        if (cls == Boolean.TYPE || cls == Boolean.class) {
            return "BooleanKind";
        }
        if (cls == Double.TYPE || cls == Double.class || cls == Float.TYPE || cls == Float.class || cls == Integer.TYPE || cls == Integer.class) {
            return "NumberKind";
        }
        if (cls == String.class) {
            return "StringKind";
        }
        if (cls == Void.TYPE) {
            return "VoidKind";
        }
        if (cls == WritableMap.class || cls == Map.class) {
            return "ObjectKind";
        }
        if (cls == WritableArray.class) {
            return "ArrayKind";
        }
        throw new ParsingException(str, str2, "Unable to parse JSI return kind. Detected unsupported return class: " + cls.getCanonicalName());
    }
}
