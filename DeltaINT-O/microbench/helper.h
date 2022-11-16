#include <time.h>

#if !defined(HELPER_H)
#define HELPER_H

/***** Timing *****/

// us
//#define CUR_TIME() (double) clock() / CLOCKS_PER_SEC * 1000.0 * 1000.0

// s + ns
#define CUR_TIME(t) clock_gettime(CLOCK_REALTIME, &t)
// t3 = t1 - t2: timespecsub(t1, t2, t3)
#define DELTA_TIME(t1, t2, t3) \
	do { \
		(t3).tv_sec = (t1).tv_sec - (t2).tv_sec; \
		(t3).tv_nsec = (t1).tv_nsec - (t2).tv_nsec; \
		if ((t3).tv_nsec < 0) { \
			(t3).tv_sec--; \
			(t3).tv_nsec += 1000000000L; \
		} \
	} while (0)
// t3 = t1 + t2: timespecadd(t1, t2, t3)
#define SUM_TIME(t1, t2, t3) \
	do { \
		(t3).tv_sec = (t1).tv_sec + (t2).tv_sec;\
		(t3).tv_nsec = (t1).tv_nsec + (t2).tv_nsec;\
		if ((t3).tv_nsec >= 1000000000L) {\
			(t3).tv_sec++;\
			(t3).tv_nsec -= 1000000000L;\
		}\
	} while (0)
// s + ns -> us
#define GET_MICROSECOND(t) (t.tv_sec * 1000 * 1000 + double(t.tv_nsec) / 1000.0)

#endif  // HELPER_H
