#include <time.h>
#include <stdio.h>
#include <sys/time.h>

#define TIME_FORMAT_SIZE 30

inline void time_format(double t, char *p)
{
	static const char * const weekday_name[] = {
		"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
	};

	static const char * const month_name[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};

	struct tm tm;
	time_t tt;

	*p = '\0';

	tt = (time_t)(long long)t;
	if (gmtime_r(&tt, &tm) == NULL)
		return;

	snprintf(p, TIME_FORMAT_SIZE,
	    "%s, %02d %s %4d %02d:%02d:%02d GMT",
	    weekday_name[tm.tm_wday],
	    tm.tm_mday, month_name[tm.tm_mon], tm.tm_year + 1900,
	    tm.tm_hour, tm.tm_min, tm.tm_sec);
}
