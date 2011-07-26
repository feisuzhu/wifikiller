/*
 * routines.h
 *
 *  Created on: 2009-11-16
 *      Author: proton
 */

#ifndef ROUTINES_H_
#define ROUTINES_H_

unsigned long fcs_crc( unsigned char * buf, int len);
libnet_t *
my_libnet_init(int injection_type, char *device, char *err_buf);

#endif /* ROUTINES_H_ */
