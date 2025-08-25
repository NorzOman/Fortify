package com.facebook.hermes.intl;

import java.util.Arrays;

/* loaded from: classes.dex */
public class OptionHelpers {

    public enum OptionType {
        BOOLEAN,
        STRING
    }

    public static Object DefaultNumberOption(String str, Object obj, Object obj2, Object obj3, Object obj4) throws JSRangeErrorException {
        if (JSObjects.isUndefined(obj)) {
            return obj4;
        }
        if (!JSObjects.isNumber(obj)) {
            throw new JSRangeErrorException(str + " value is invalid.");
        }
        double javaDouble = JSObjects.getJavaDouble(obj);
        if (Double.isNaN(javaDouble) || javaDouble > JSObjects.getJavaDouble(obj3) || javaDouble < JSObjects.getJavaDouble(obj2)) {
            throw new JSRangeErrorException(str + " value is invalid.");
        }
        return obj;
    }

    public static Object GetNumberOption(Object obj, String str, Object obj2, Object obj3, Object obj4) throws JSRangeErrorException {
        return DefaultNumberOption(str, JSObjects.Get(obj, str), obj2, obj3, obj4);
    }

    public static Object GetOption(Object obj, String str, OptionType optionType, Object obj2, Object obj3) throws JSRangeErrorException {
        Object objGet = JSObjects.Get(obj, str);
        if (JSObjects.isUndefined(objGet)) {
            return obj3;
        }
        if (JSObjects.isNull(objGet)) {
            objGet = "";
        }
        if (optionType == OptionType.BOOLEAN && !JSObjects.isBoolean(objGet)) {
            throw new JSRangeErrorException("Boolean option expected but not found");
        }
        if (optionType == OptionType.STRING && !JSObjects.isString(objGet)) {
            throw new JSRangeErrorException("String option expected but not found");
        }
        if (JSObjects.isUndefined(obj2) || Arrays.asList((Object[]) obj2).contains(objGet)) {
            return objGet;
        }
        throw new JSRangeErrorException("String option expected but not found");
    }

    public static <T extends Enum<T>> T searchEnum(Class<T> cls, Object obj) {
        if (JSObjects.isUndefined(obj)) {
            return (T) Enum.valueOf(cls, "UNDEFINED");
        }
        if (JSObjects.isNull(obj)) {
            return null;
        }
        String javaString = JSObjects.getJavaString(obj);
        if (javaString.equals("2-digit")) {
            return (T) Enum.valueOf(cls, "DIGIT2");
        }
        for (T t : cls.getEnumConstants()) {
            if (t.name().compareToIgnoreCase(javaString) == 0) {
                return t;
            }
        }
        return null;
    }
}
