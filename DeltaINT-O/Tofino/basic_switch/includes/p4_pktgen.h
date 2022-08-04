#ifndef _P4_PKTGEN_H_
#define _P4_PKTGEN_H_

#define P4_PKTGEN_TIMER_ONE_SHOT 0x0
#define P4_PKTGEN_PERIODIC 0x1
#define P4_PKTGEN_PORT_DOWN 0x2
#define P4_PKTGEN_RECIRC 0x3

/* AppIds 0-7 for various pktgen applications */
#define P4_PKTGEN_APP_BFD      0x0
#define P4_PKTGEN_APP_LAG_FAILOVER 0x1
#define P4_PKTGEN_APP_ECMP_FAILOVER 0x2

#endif /* _P4_PKTGEN_H_ */
