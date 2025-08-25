package com.facebook.hermes.intl;

import com.facebook.hermes.intl.IPlatformDateTimeFormatter;
import java.text.AttributedCharacterIterator;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/* loaded from: classes.dex */
public class PlatformDateTimeFormatterAndroid implements IPlatformDateTimeFormatter {
    private DateFormat mDateFormat = null;

    @Override // com.facebook.hermes.intl.IPlatformDateTimeFormatter
    public String format(double d) {
        return this.mDateFormat.format(new Date((long) d));
    }

    @Override // com.facebook.hermes.intl.IPlatformDateTimeFormatter
    public String fieldToString(AttributedCharacterIterator.Attribute attribute, String str) throws NumberFormatException {
        if (attribute == DateFormat.Field.DAY_OF_WEEK) {
            return "weekday";
        }
        if (attribute == DateFormat.Field.ERA) {
            return "era";
        }
        if (attribute == DateFormat.Field.YEAR) {
            try {
                Double.parseDouble(str);
                return "year";
            } catch (NumberFormatException unused) {
                return "yearName";
            }
        }
        if (attribute == DateFormat.Field.MONTH) {
            return "month";
        }
        if (attribute == DateFormat.Field.DAY_OF_MONTH) {
            return "day";
        }
        if (attribute == DateFormat.Field.HOUR0 || attribute == DateFormat.Field.HOUR1 || attribute == DateFormat.Field.HOUR_OF_DAY0 || attribute == DateFormat.Field.HOUR_OF_DAY1) {
            return "hour";
        }
        if (attribute == DateFormat.Field.MINUTE) {
            return "minute";
        }
        if (attribute == DateFormat.Field.SECOND) {
            return "second";
        }
        if (attribute == DateFormat.Field.TIME_ZONE) {
            return "timeZoneName";
        }
        if (attribute == DateFormat.Field.AM_PM) {
            return "dayPeriod";
        }
        if (attribute.toString().equals("android.icu.text.DateFormat$Field(related year)")) {
            return "relatedYear";
        }
        return "literal";
    }

    @Override // com.facebook.hermes.intl.IPlatformDateTimeFormatter
    public AttributedCharacterIterator formatToParts(double d) {
        return this.mDateFormat.formatToCharacterIterator(Double.valueOf(d));
    }

    @Override // com.facebook.hermes.intl.IPlatformDateTimeFormatter
    public String getDefaultCalendarName(ILocaleObject<?> iLocaleObject) throws JSRangeErrorException {
        return DateFormat.getDateInstance(3, (Locale) iLocaleObject.getLocale()).getCalendar().toString();
    }

    private static class PatternUtils {
        private PatternUtils() {
        }

        public static String getPatternWithoutLiterals(String str) {
            StringBuilder sb = new StringBuilder();
            boolean z = false;
            for (int i = 0; i < str.length(); i++) {
                char cCharAt = str.charAt(i);
                if (cCharAt == '\'') {
                    z = !z;
                } else if (!z && ((cCharAt >= 'A' && cCharAt <= 'Z') || (cCharAt >= 'a' && cCharAt <= 'z'))) {
                    sb.append(str.charAt(i));
                }
            }
            return sb.toString();
        }
    }

    @Override // com.facebook.hermes.intl.IPlatformDateTimeFormatter
    public IPlatformDateTimeFormatter.HourCycle getDefaultHourCycle(ILocaleObject<?> iLocaleObject) throws JSRangeErrorException {
        IPlatformDateTimeFormatter.HourCycle hourCycle;
        try {
            String patternWithoutLiterals = PatternUtils.getPatternWithoutLiterals(((SimpleDateFormat) DateFormat.getTimeInstance(0, (Locale) iLocaleObject.getLocale())).toPattern());
            if (patternWithoutLiterals.contains(String.valueOf('h'))) {
                hourCycle = IPlatformDateTimeFormatter.HourCycle.H12;
            } else if (patternWithoutLiterals.contains(String.valueOf('K'))) {
                hourCycle = IPlatformDateTimeFormatter.HourCycle.H11;
            } else if (patternWithoutLiterals.contains(String.valueOf('H'))) {
                hourCycle = IPlatformDateTimeFormatter.HourCycle.H23;
            } else {
                hourCycle = IPlatformDateTimeFormatter.HourCycle.H24;
            }
            return hourCycle;
        } catch (ClassCastException unused) {
            return IPlatformDateTimeFormatter.HourCycle.H24;
        }
    }

    @Override // com.facebook.hermes.intl.IPlatformDateTimeFormatter
    public String getDefaultTimeZone(ILocaleObject<?> iLocaleObject) throws JSRangeErrorException {
        return Calendar.getInstance((Locale) iLocaleObject.getLocale()).getTimeZone().getID();
    }

    @Override // com.facebook.hermes.intl.IPlatformDateTimeFormatter
    public String getDefaultNumberingSystem(ILocaleObject<?> iLocaleObject) {
        return "latn";
    }

    @Override // com.facebook.hermes.intl.IPlatformDateTimeFormatter
    public void configure(ILocaleObject<?> iLocaleObject, String str, String str2, IPlatformDateTimeFormatter.FormatMatcher formatMatcher, IPlatformDateTimeFormatter.WeekDay weekDay, IPlatformDateTimeFormatter.Era era, IPlatformDateTimeFormatter.Year year, IPlatformDateTimeFormatter.Month month, IPlatformDateTimeFormatter.Day day, IPlatformDateTimeFormatter.Hour hour, IPlatformDateTimeFormatter.Minute minute, IPlatformDateTimeFormatter.Second second, IPlatformDateTimeFormatter.TimeZoneName timeZoneName, IPlatformDateTimeFormatter.HourCycle hourCycle, Object obj, IPlatformDateTimeFormatter.DateStyle dateStyle, IPlatformDateTimeFormatter.TimeStyle timeStyle, Object obj2) throws JSRangeErrorException {
        if (!str.isEmpty()) {
            ArrayList<String> arrayList = new ArrayList<>();
            arrayList.add(JSObjects.getJavaString(str));
            iLocaleObject.setUnicodeExtensions("ca", arrayList);
        }
        if (!str2.isEmpty()) {
            ArrayList<String> arrayList2 = new ArrayList<>();
            arrayList2.add(JSObjects.getJavaString(str2));
            iLocaleObject.setUnicodeExtensions("nu", arrayList2);
        }
        boolean z = true;
        boolean z2 = (year == null && month == null && day == null) ? false : true;
        if (hour == null && minute == null && second == null) {
            z = false;
        }
        if (z2 && z) {
            this.mDateFormat = DateFormat.getDateTimeInstance(0, 0, (Locale) iLocaleObject.getLocale());
        } else if (z2) {
            this.mDateFormat = DateFormat.getDateInstance(0, (Locale) iLocaleObject.getLocale());
        } else if (z) {
            this.mDateFormat = DateFormat.getTimeInstance(0, (Locale) iLocaleObject.getLocale());
        }
        if (JSObjects.isUndefined(obj) || JSObjects.isNull(obj)) {
            return;
        }
        this.mDateFormat.setTimeZone(TimeZone.getTimeZone(JSObjects.getJavaString(obj)));
    }

    @Override // com.facebook.hermes.intl.IPlatformDateTimeFormatter
    public String[] getAvailableLocales() {
        ArrayList arrayList = new ArrayList();
        for (Locale locale : DateFormat.getAvailableLocales()) {
            arrayList.add(locale.toLanguageTag());
        }
        return (String[]) arrayList.toArray(new String[arrayList.size()]);
    }

    PlatformDateTimeFormatterAndroid() {
    }
}
