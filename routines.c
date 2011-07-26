/*
 * routines.c
 *
 *  Created on: 2009-11-16
 *      Author: proton
 */

#include <sys/time.h>

#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>

#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */

#include <libnet.h>

int
my_libnet_open_link(libnet_t *l)
{
    struct ifreq ifr;
    int n = 1;

    if (l == NULL)
    {
        return (-1);
    }

    l->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (l->fd == -1)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                "socket: %s", strerror(errno));
        goto bad;
    }

    memset(&ifr, 0, sizeof (ifr));
    strncpy(ifr.ifr_name, l->device, sizeof (ifr.ifr_name) -1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    if (ioctl(l->fd, SIOCGIFHWADDR, &ifr) < 0 )
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                "SIOCGIFHWADDR: %s", strerror(errno));
        goto bad;
    }

    switch (ifr.ifr_hwaddr.sa_family)
    {
        //{{BEGIN_PROTON_ADDED_CODE}}
        case ARPHRD_IEEE80211_RADIOTAP:
        	l->link_type = 0x123; //What ever
        	l->link_offset = 0x20; //Don't know what is it, but we don't use libnet_build* funcs.
        	break;
        //{{END_PROTON_ADDED_CODE}}

        default:
            snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                "unknown physical layer type 0x%x\n",
                ifr.ifr_hwaddr.sa_family);
        goto bad;
    }

    if (setsockopt(l->fd, SOL_SOCKET, SO_BROADCAST, &n, sizeof(n)) == -1)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
		 "%s: set SO_BROADCAST failed: %s\n",
		 __func__, strerror(errno));
        goto bad;
    }
    return (1);

bad:
    if (l->fd >= 0)
    {
        close(l->fd);
    }
    return (-1);
}


libnet_t *
my_libnet_init(int injection_type, char *device, char *err_buf)
{
    libnet_t *l = NULL;

    if (getuid() && geteuid())
    {
        snprintf(err_buf, LIBNET_ERRBUF_SIZE,
                "%s(): UID or EUID of 0 required\n", __func__);
        goto bad;
    }

    l = (libnet_t *)malloc(sizeof (libnet_t));
    if (l == NULL)
    {
        snprintf(err_buf, LIBNET_ERRBUF_SIZE, "%s(): malloc(): %s\n", __func__,
                strerror(errno));
        goto bad;
    }

    memset(l, 0, sizeof (*l));

    l->injection_type   = injection_type;
    l->ptag_state       = LIBNET_PTAG_INITIALIZER;
    l->device           = (device ? strdup(device) : NULL);

    strncpy(l->label, LIBNET_LABEL_DEFAULT, LIBNET_LABEL_SIZE);
    l->label[sizeof(l->label)] = '\0';

    switch (l->injection_type)
    {
        case LIBNET_LINK:
        case LIBNET_LINK_ADV:
            if (libnet_select_device(l) == -1)
            {
                snprintf(err_buf, LIBNET_ERRBUF_SIZE, l->err_buf);
		goto bad;
            }
            if (my_libnet_open_link(l) == -1)
            {
                snprintf(err_buf, LIBNET_ERRBUF_SIZE, l->err_buf);
                goto bad;
            }
            break;
        default:
            snprintf(err_buf, LIBNET_ERRBUF_SIZE,
                    "%s(): unsupported injection type\n", __func__);
            goto bad;
            break;
    }

    return (l);

bad:
    if (l)
    {
        libnet_destroy(l);
    }
    return (NULL);
}
