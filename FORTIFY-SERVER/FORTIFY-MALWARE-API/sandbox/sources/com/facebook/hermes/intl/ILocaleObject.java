package com.facebook.hermes.intl;

import java.util.ArrayList;
import java.util.HashMap;

/* loaded from: classes.dex */
public interface ILocaleObject<T> {
    ILocaleObject<T> cloneObject() throws JSRangeErrorException;

    T getLocale() throws JSRangeErrorException;

    T getLocaleWithoutExtensions() throws JSRangeErrorException;

    ArrayList<String> getUnicodeExtensions(String str) throws JSRangeErrorException;

    HashMap<String, String> getUnicodeExtensions() throws JSRangeErrorException;

    void setUnicodeExtensions(String str, ArrayList<String> arrayList) throws JSRangeErrorException;

    String toCanonicalTag() throws JSRangeErrorException;

    String toCanonicalTagWithoutExtensions() throws JSRangeErrorException;
}
