package com.facebook.hermes.intl;

import androidx.core.text.util.LocalePreferences;
import com.facebook.hermes.intl.IPlatformDateTimeFormatter;
import com.facebook.hermes.intl.OptionHelpers;
import java.text.AttributedCharacterIterator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

/* loaded from: classes.dex */
public class DateTimeFormat {
    private String mCalendar;
    private IPlatformDateTimeFormatter.DateStyle mDateStyle;
    private IPlatformDateTimeFormatter.Day mDay;
    private IPlatformDateTimeFormatter.Era mEra;
    private IPlatformDateTimeFormatter.FormatMatcher mFormatMatcher;
    private IPlatformDateTimeFormatter.Hour mHour;
    private Object mHour12;
    private IPlatformDateTimeFormatter.HourCycle mHourCycle;
    private IPlatformDateTimeFormatter.Minute mMinute;
    private IPlatformDateTimeFormatter.Month mMonth;
    private String mNumberingSystem;
    private IPlatformDateTimeFormatter.Second mSecond;
    private IPlatformDateTimeFormatter.TimeStyle mTimeStyle;
    private IPlatformDateTimeFormatter.TimeZoneName mTimeZoneName;
    private IPlatformDateTimeFormatter.WeekDay mWeekDay;
    private IPlatformDateTimeFormatter.Year mYear;
    private boolean useDefaultCalendar;
    private boolean useDefaultNumberSystem;
    private ILocaleObject<?> mResolvedLocaleObject = null;
    private ILocaleObject<?> mResolvedLocaleObjectForResolvedOptions = null;
    private Object mTimeZone = null;
    IPlatformDateTimeFormatter mPlatformDateTimeFormatter = new PlatformDateTimeFormatterICU();

    private boolean isLocaleIdType(String str) {
        return IntlTextUtils.isUnicodeExtensionKeyTypeItem(str, 0, str.length() - 1);
    }

    private Object ToDateTimeOptions(Object obj, String str, String str2) throws JSRangeErrorException {
        boolean z;
        if (!JSObjects.isObject(obj)) {
            throw new JSRangeErrorException("Invalid options object !");
        }
        if (str.equals("date") || str.equals("any")) {
            String[] strArr = {"weekday", "year", "month", "day"};
            z = true;
            int i = 0;
            for (int i2 = 4; i < i2; i2 = 4) {
                if (!JSObjects.isUndefined(JSObjects.Get(obj, strArr[i]))) {
                    z = false;
                }
                i++;
            }
        } else {
            z = true;
        }
        if (str.equals("time") || str.equals("any")) {
            String[] strArr2 = {"hour", "minute", "second"};
            for (int i3 = 0; i3 < 3; i3++) {
                if (!JSObjects.isUndefined(JSObjects.Get(obj, strArr2[i3]))) {
                    z = false;
                }
            }
        }
        if (!JSObjects.isUndefined(JSObjects.Get(obj, "dateStyle")) || !JSObjects.isUndefined(JSObjects.Get(obj, "timeStyle"))) {
            z = false;
        }
        if (z && (str2.equals("date") || str2.equals("all"))) {
            String[] strArr3 = {"year", "month", "day"};
            for (int i4 = 0; i4 < 3; i4++) {
                JSObjects.Put(obj, strArr3[i4], Constants.COLLATION_OPTION_NUMERIC);
            }
        }
        if (z && (str2.equals("time") || str2.equals("all"))) {
            String[] strArr4 = {"hour", "minute", "second"};
            for (int i5 = 0; i5 < 3; i5++) {
                JSObjects.Put(obj, strArr4[i5], Constants.COLLATION_OPTION_NUMERIC);
            }
        }
        return obj;
    }

    public String normalizeTimeZoneName(String str) {
        StringBuilder sb = new StringBuilder(str.length());
        for (int i = 0; i < str.length(); i++) {
            char cCharAt = str.charAt(i);
            if (cCharAt >= 'A' && cCharAt <= 'Z') {
                sb.append((char) (cCharAt + ' '));
            } else {
                sb.append(cCharAt);
            }
        }
        return sb.toString();
    }

    public String normalizeTimeZone(String str) throws JSRangeErrorException {
        for (String str2 : TimeZone.getAvailableIDs()) {
            if (normalizeTimeZoneName(str2).equals(normalizeTimeZoneName(str))) {
                return str2;
            }
        }
        throw new JSRangeErrorException("Invalid timezone name!");
    }

    private Object DefaultTimeZone() throws JSRangeErrorException {
        return this.mPlatformDateTimeFormatter.getDefaultTimeZone(this.mResolvedLocaleObject);
    }

    private void initializeDateTimeFormat(List<String> list, Map<String, Object> map) throws JSRangeErrorException {
        Object objNormalizeTimeZone;
        List listAsList = Arrays.asList("ca", "nu", "hc");
        Object objToDateTimeOptions = ToDateTimeOptions(map, "any", "date");
        Object objNewObject = JSObjects.newObject();
        JSObjects.Put(objNewObject, Constants.LOCALEMATCHER, OptionHelpers.GetOption(objToDateTimeOptions, Constants.LOCALEMATCHER, OptionHelpers.OptionType.STRING, Constants.LOCALEMATCHER_POSSIBLE_VALUES, Constants.LOCALEMATCHER_BESTFIT));
        Object objGetOption = OptionHelpers.GetOption(objToDateTimeOptions, "calendar", OptionHelpers.OptionType.STRING, JSObjects.Undefined(), JSObjects.Undefined());
        if (!JSObjects.isUndefined(objGetOption) && !isLocaleIdType(JSObjects.getJavaString(objGetOption))) {
            throw new JSRangeErrorException("Invalid calendar option !");
        }
        JSObjects.Put(objNewObject, "ca", objGetOption);
        Object objGetOption2 = OptionHelpers.GetOption(objToDateTimeOptions, "numberingSystem", OptionHelpers.OptionType.STRING, JSObjects.Undefined(), JSObjects.Undefined());
        if (!JSObjects.isUndefined(objGetOption2) && !isLocaleIdType(JSObjects.getJavaString(objGetOption2))) {
            throw new JSRangeErrorException("Invalid numbering system !");
        }
        JSObjects.Put(objNewObject, "nu", objGetOption2);
        Object objGetOption3 = OptionHelpers.GetOption(objToDateTimeOptions, "hour12", OptionHelpers.OptionType.BOOLEAN, JSObjects.Undefined(), JSObjects.Undefined());
        Object objGetOption4 = OptionHelpers.GetOption(objToDateTimeOptions, "hourCycle", OptionHelpers.OptionType.STRING, new String[]{LocalePreferences.HourCycle.H11, LocalePreferences.HourCycle.H12, LocalePreferences.HourCycle.H23, LocalePreferences.HourCycle.H24}, JSObjects.Undefined());
        if (!JSObjects.isUndefined(objGetOption3)) {
            objGetOption4 = JSObjects.Null();
        }
        JSObjects.Put(objNewObject, "hc", objGetOption4);
        HashMap<String, Object> mapResolveLocale = LocaleResolver.resolveLocale(list, objNewObject, listAsList);
        ILocaleObject<?> iLocaleObject = (ILocaleObject) JSObjects.getJavaMap(mapResolveLocale).get(Constants.LOCALE);
        this.mResolvedLocaleObject = iLocaleObject;
        this.mResolvedLocaleObjectForResolvedOptions = iLocaleObject.cloneObject();
        Object objGet = JSObjects.Get(mapResolveLocale, "ca");
        if (!JSObjects.isNull(objGet)) {
            this.useDefaultCalendar = false;
            this.mCalendar = JSObjects.getJavaString(objGet);
        } else {
            this.useDefaultCalendar = true;
            this.mCalendar = this.mPlatformDateTimeFormatter.getDefaultCalendarName(this.mResolvedLocaleObject);
        }
        Object objGet2 = JSObjects.Get(mapResolveLocale, "nu");
        if (!JSObjects.isNull(objGet2)) {
            this.useDefaultNumberSystem = false;
            this.mNumberingSystem = JSObjects.getJavaString(objGet2);
        } else {
            this.useDefaultNumberSystem = true;
            this.mNumberingSystem = this.mPlatformDateTimeFormatter.getDefaultNumberingSystem(this.mResolvedLocaleObject);
        }
        Object objGet3 = JSObjects.Get(mapResolveLocale, "hc");
        Object objGet4 = JSObjects.Get(objToDateTimeOptions, "timeZone");
        if (JSObjects.isUndefined(objGet4)) {
            objNormalizeTimeZone = DefaultTimeZone();
        } else {
            objNormalizeTimeZone = normalizeTimeZone(objGet4.toString());
        }
        this.mTimeZone = objNormalizeTimeZone;
        this.mFormatMatcher = (IPlatformDateTimeFormatter.FormatMatcher) OptionHelpers.searchEnum(IPlatformDateTimeFormatter.FormatMatcher.class, JSObjects.getJavaString(OptionHelpers.GetOption(objToDateTimeOptions, "formatMatcher", OptionHelpers.OptionType.STRING, new String[]{"basic", Constants.LOCALEMATCHER_BESTFIT}, Constants.LOCALEMATCHER_BESTFIT)));
        this.mWeekDay = (IPlatformDateTimeFormatter.WeekDay) OptionHelpers.searchEnum(IPlatformDateTimeFormatter.WeekDay.class, OptionHelpers.GetOption(objToDateTimeOptions, "weekday", OptionHelpers.OptionType.STRING, new String[]{"long", "short", "narrow"}, JSObjects.Undefined()));
        this.mEra = (IPlatformDateTimeFormatter.Era) OptionHelpers.searchEnum(IPlatformDateTimeFormatter.Era.class, OptionHelpers.GetOption(objToDateTimeOptions, "era", OptionHelpers.OptionType.STRING, new String[]{"long", "short", "narrow"}, JSObjects.Undefined()));
        this.mYear = (IPlatformDateTimeFormatter.Year) OptionHelpers.searchEnum(IPlatformDateTimeFormatter.Year.class, OptionHelpers.GetOption(objToDateTimeOptions, "year", OptionHelpers.OptionType.STRING, new String[]{Constants.COLLATION_OPTION_NUMERIC, "2-digit"}, JSObjects.Undefined()));
        this.mMonth = (IPlatformDateTimeFormatter.Month) OptionHelpers.searchEnum(IPlatformDateTimeFormatter.Month.class, OptionHelpers.GetOption(objToDateTimeOptions, "month", OptionHelpers.OptionType.STRING, new String[]{Constants.COLLATION_OPTION_NUMERIC, "2-digit", "long", "short", "narrow"}, JSObjects.Undefined()));
        this.mDay = (IPlatformDateTimeFormatter.Day) OptionHelpers.searchEnum(IPlatformDateTimeFormatter.Day.class, OptionHelpers.GetOption(objToDateTimeOptions, "day", OptionHelpers.OptionType.STRING, new String[]{Constants.COLLATION_OPTION_NUMERIC, "2-digit"}, JSObjects.Undefined()));
        Object objGetOption5 = OptionHelpers.GetOption(objToDateTimeOptions, "hour", OptionHelpers.OptionType.STRING, new String[]{Constants.COLLATION_OPTION_NUMERIC, "2-digit"}, JSObjects.Undefined());
        this.mHour = (IPlatformDateTimeFormatter.Hour) OptionHelpers.searchEnum(IPlatformDateTimeFormatter.Hour.class, objGetOption5);
        this.mMinute = (IPlatformDateTimeFormatter.Minute) OptionHelpers.searchEnum(IPlatformDateTimeFormatter.Minute.class, OptionHelpers.GetOption(objToDateTimeOptions, "minute", OptionHelpers.OptionType.STRING, new String[]{Constants.COLLATION_OPTION_NUMERIC, "2-digit"}, JSObjects.Undefined()));
        this.mSecond = (IPlatformDateTimeFormatter.Second) OptionHelpers.searchEnum(IPlatformDateTimeFormatter.Second.class, OptionHelpers.GetOption(objToDateTimeOptions, "second", OptionHelpers.OptionType.STRING, new String[]{Constants.COLLATION_OPTION_NUMERIC, "2-digit"}, JSObjects.Undefined()));
        this.mTimeZoneName = (IPlatformDateTimeFormatter.TimeZoneName) OptionHelpers.searchEnum(IPlatformDateTimeFormatter.TimeZoneName.class, OptionHelpers.GetOption(objToDateTimeOptions, "timeZoneName", OptionHelpers.OptionType.STRING, new String[]{"long", "longOffset", "longGeneric", "short", "shortOffset", "shortGeneric"}, JSObjects.Undefined()));
        this.mDateStyle = (IPlatformDateTimeFormatter.DateStyle) OptionHelpers.searchEnum(IPlatformDateTimeFormatter.DateStyle.class, OptionHelpers.GetOption(objToDateTimeOptions, "dateStyle", OptionHelpers.OptionType.STRING, new String[]{"full", "long", "medium", "short"}, JSObjects.Undefined()));
        Object objGetOption6 = OptionHelpers.GetOption(objToDateTimeOptions, "timeStyle", OptionHelpers.OptionType.STRING, new String[]{"full", "long", "medium", "short"}, JSObjects.Undefined());
        this.mTimeStyle = (IPlatformDateTimeFormatter.TimeStyle) OptionHelpers.searchEnum(IPlatformDateTimeFormatter.TimeStyle.class, objGetOption6);
        if (JSObjects.isUndefined(objGetOption5) && JSObjects.isUndefined(objGetOption6)) {
            this.mHourCycle = IPlatformDateTimeFormatter.HourCycle.UNDEFINED;
        } else {
            IPlatformDateTimeFormatter.HourCycle defaultHourCycle = this.mPlatformDateTimeFormatter.getDefaultHourCycle(this.mResolvedLocaleObject);
            IPlatformDateTimeFormatter.HourCycle hourCycle = JSObjects.isNull(objGet3) ? defaultHourCycle : (IPlatformDateTimeFormatter.HourCycle) OptionHelpers.searchEnum(IPlatformDateTimeFormatter.HourCycle.class, objGet3);
            if (!JSObjects.isUndefined(objGetOption3)) {
                if (JSObjects.getJavaBoolean(objGetOption3)) {
                    if (defaultHourCycle == IPlatformDateTimeFormatter.HourCycle.H11 || defaultHourCycle == IPlatformDateTimeFormatter.HourCycle.H23) {
                        hourCycle = IPlatformDateTimeFormatter.HourCycle.H11;
                    } else {
                        hourCycle = IPlatformDateTimeFormatter.HourCycle.H12;
                    }
                } else if (defaultHourCycle == IPlatformDateTimeFormatter.HourCycle.H11 || defaultHourCycle == IPlatformDateTimeFormatter.HourCycle.H23) {
                    hourCycle = IPlatformDateTimeFormatter.HourCycle.H23;
                } else {
                    hourCycle = IPlatformDateTimeFormatter.HourCycle.H24;
                }
            }
            this.mHourCycle = hourCycle;
        }
        this.mHour12 = objGetOption3;
    }

    public DateTimeFormat(List<String> list, Map<String, Object> map) throws JSRangeErrorException {
        initializeDateTimeFormat(list, map);
        this.mPlatformDateTimeFormatter.configure(this.mResolvedLocaleObject, this.useDefaultCalendar ? "" : this.mCalendar, this.useDefaultNumberSystem ? "" : this.mNumberingSystem, this.mFormatMatcher, this.mWeekDay, this.mEra, this.mYear, this.mMonth, this.mDay, this.mHour, this.mMinute, this.mSecond, this.mTimeZoneName, this.mHourCycle, this.mTimeZone, this.mDateStyle, this.mTimeStyle, this.mHour12);
    }

    public static List<String> supportedLocalesOf(List<String> list, Map<String, Object> map) throws JSRangeErrorException {
        String javaString = JSObjects.getJavaString(OptionHelpers.GetOption(map, Constants.LOCALEMATCHER, OptionHelpers.OptionType.STRING, Constants.LOCALEMATCHER_POSSIBLE_VALUES, Constants.LOCALEMATCHER_BESTFIT));
        String[] strArr = new String[list.size()];
        if (javaString.equals(Constants.LOCALEMATCHER_BESTFIT)) {
            return Arrays.asList(LocaleMatcher.bestFitSupportedLocales((String[]) list.toArray(strArr)));
        }
        return Arrays.asList(LocaleMatcher.lookupSupportedLocales((String[]) list.toArray(strArr)));
    }

    public Map<String, Object> resolvedOptions() throws JSRangeErrorException {
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        linkedHashMap.put(Constants.LOCALE, this.mResolvedLocaleObjectForResolvedOptions.toCanonicalTag());
        linkedHashMap.put("numberingSystem", this.mNumberingSystem);
        linkedHashMap.put("calendar", this.mCalendar);
        linkedHashMap.put("timeZone", this.mTimeZone);
        if (this.mHourCycle != IPlatformDateTimeFormatter.HourCycle.UNDEFINED) {
            linkedHashMap.put("hourCycle", this.mHourCycle.toString());
            if (this.mHourCycle == IPlatformDateTimeFormatter.HourCycle.H11 || this.mHourCycle == IPlatformDateTimeFormatter.HourCycle.H12) {
                linkedHashMap.put("hour12", true);
            } else {
                linkedHashMap.put("hour12", false);
            }
        }
        if (this.mWeekDay != IPlatformDateTimeFormatter.WeekDay.UNDEFINED) {
            linkedHashMap.put("weekday", this.mWeekDay.toString());
        }
        if (this.mEra != IPlatformDateTimeFormatter.Era.UNDEFINED) {
            linkedHashMap.put("era", this.mEra.toString());
        }
        if (this.mYear != IPlatformDateTimeFormatter.Year.UNDEFINED) {
            linkedHashMap.put("year", this.mYear.toString());
        }
        if (this.mMonth != IPlatformDateTimeFormatter.Month.UNDEFINED) {
            linkedHashMap.put("month", this.mMonth.toString());
        }
        if (this.mDay != IPlatformDateTimeFormatter.Day.UNDEFINED) {
            linkedHashMap.put("day", this.mDay.toString());
        }
        if (this.mHour != IPlatformDateTimeFormatter.Hour.UNDEFINED) {
            linkedHashMap.put("hour", this.mHour.toString());
        }
        if (this.mMinute != IPlatformDateTimeFormatter.Minute.UNDEFINED) {
            linkedHashMap.put("minute", this.mMinute.toString());
        }
        if (this.mSecond != IPlatformDateTimeFormatter.Second.UNDEFINED) {
            linkedHashMap.put("second", this.mSecond.toString());
        }
        if (this.mTimeZoneName != IPlatformDateTimeFormatter.TimeZoneName.UNDEFINED) {
            linkedHashMap.put("timeZoneName", this.mTimeZoneName.toString());
        }
        if (this.mDateStyle != IPlatformDateTimeFormatter.DateStyle.UNDEFINED) {
            linkedHashMap.put("dateStyle", this.mDateStyle.toString());
        }
        if (this.mTimeStyle != IPlatformDateTimeFormatter.TimeStyle.UNDEFINED) {
            linkedHashMap.put("timeStyle", this.mTimeStyle.toString());
        }
        return linkedHashMap;
    }

    public String format(double d) throws JSRangeErrorException {
        return this.mPlatformDateTimeFormatter.format(d);
    }

    public List<Map<String, String>> formatToParts(double d) throws JSRangeErrorException {
        String strFieldToString;
        ArrayList arrayList = new ArrayList();
        AttributedCharacterIterator toParts = this.mPlatformDateTimeFormatter.formatToParts(d);
        StringBuilder sb = new StringBuilder();
        for (char cFirst = toParts.first(); cFirst != 65535; cFirst = toParts.next()) {
            sb.append(cFirst);
            if (toParts.getIndex() + 1 == toParts.getRunLimit()) {
                Iterator<AttributedCharacterIterator.Attribute> it = toParts.getAttributes().keySet().iterator();
                if (it.hasNext()) {
                    strFieldToString = this.mPlatformDateTimeFormatter.fieldToString(it.next(), sb.toString());
                } else {
                    strFieldToString = "literal";
                }
                String string = sb.toString();
                sb.setLength(0);
                HashMap map = new HashMap();
                map.put("type", strFieldToString);
                map.put("value", string);
                arrayList.add(map);
            }
        }
        return arrayList;
    }
}
