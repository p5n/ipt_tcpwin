/* TCP window modification module for IP tables
 * (C) 2015 by Sergej Pupykin <sergej@p5n.pp.ru> */

#ifndef _IPT_TWIN_H
#define _IPT_TWIN_H

#include <linux/types.h>

struct ipt_TWIN_info {
	__u16	win;
};

#endif
