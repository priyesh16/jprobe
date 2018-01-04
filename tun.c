#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <stddef.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/rtnetlink.h>
#include <linux/filter.h>

#ifndef __constant_htons
#define __constant_htons(x)  htons(x)
#endif

#include <linux/if_tunnel.h>

#define IP_DF      0x4000      /* Flag: "Don't Fragment"   */
#define PREFIXNAME "pri"
#define PREFIXADDR "12.2.3."
char myTunnels[100][IFNAMSIZ];
typedef struct
{
   __u8 family;
   __u8 bytelen;
   __s16 bitlen;
   __u32 flags;
   __u32 data[8];
} inet_prefix;
/* This uses a non-standard parsing (ie not inet_aton, or inet_pton)
 * because of legacy choice to parse 10.8 as 10.8.0.0 not 10.0.0.8
 */
static int get_addr_ipv4(__u8 *ap, const char *cp)
{
	int i;
	for (i = 0; i < 4; i++) {
		unsigned long n;
		char *endp;
		
		n = strtoul(cp, &endp, 0);
		if (n > 255)
			return -1;	/* bogus network value */
		if (endp == cp) /* no digits */
			return -1;
		ap[i] = n;
		if (*endp == '\0')
			break;
		if (i == 3 || *endp != '.')
			return -1; 	/* extra characters */
		cp = endp + 1;
	}
	return 1;
}

__u32 get_addr32(const char *name)
{
	inet_prefix addr;
	memset(&addr, 0, sizeof(addr));
	addr.family = AF_INET;
	if (get_addr_ipv4((__u8 *)addr.data, name) <= 0)
		return -1;

	addr.bytelen = 4;
	addr.bitlen = -1;
	return addr.data[0];
}

static int do_ioctl_get_ifindex(const char *dev)
{
   struct ifreq ifr;
   int fd;
   int err;

   strncpy(ifr.ifr_name, dev, IFNAMSIZ);
   fd = socket(AF_INET, SOCK_DGRAM, 0);
   err = ioctl(fd, SIOCGIFINDEX, &ifr);
   if (err) {
      perror("ioctl");
      return 0;
   }
   close(fd);
   return ifr.ifr_ifindex;
}

static int do_ioctl_get_iftype(const char *dev)
{
   struct ifreq ifr;
   int fd;
   int err;

   strncpy(ifr.ifr_name, dev, IFNAMSIZ);
   fd = socket(AF_INET, SOCK_DGRAM, 0);
   err = ioctl(fd, SIOCGIFHWADDR, &ifr);
   if (err) {
      perror("ioctl");
      return -1;
   }
   close(fd);
   return ifr.ifr_addr.sa_family;
}


static char * do_ioctl_get_ifname(int idx)
{
   static struct ifreq ifr;
   int fd;
   int err;

   ifr.ifr_ifindex = idx;
   fd = socket(AF_INET, SOCK_DGRAM, 0);
   err = ioctl(fd, SIOCGIFNAME, &ifr);
   if (err) {
      perror("ioctl");
      return NULL;
   }
   close(fd);
   return ifr.ifr_name;
}


static int do_get_ioctl(const char *basedev, struct ip_tunnel_parm *p)
{
   struct ifreq ifr;
   int fd;
   int err;

   strncpy(ifr.ifr_name, basedev, IFNAMSIZ);
   ifr.ifr_ifru.ifru_data = (void*)p;
   fd = socket(AF_INET, SOCK_DGRAM, 0);
   err = ioctl(fd, SIOCGETTUNNEL, &ifr);
   if (err)
      perror("ioctl");
   close(fd);
   return err;
}

static int parseArgs(int cmd, struct ip_tunnel_parm *p, const char* dev, const char* addr)
{
   int count = 0;
   char medium[IFNAMSIZ];
   unsigned char buf[sizeof(struct in6_addr)];

   memset(p, 0, sizeof(*p));
   memset(&medium, 0, sizeof(medium));

   p->iph.version = 4;
   p->iph.ihl = 5;
   p->iph.frag_off = htons(IP_DF);
   p->iph.protocol = IPPROTO_GRE;
   if (addr != NULL) {
      p->iph.daddr = get_addr32(addr);
   }
   if (dev != NULL) {
      strncpy(p->name, dev, IFNAMSIZ);
   }
   return 0;
}
static int addTunnel(const char *index)
{
   struct ifreq ifr;
   int fd;
   int err;
   int cmd = SIOCADDTUNNEL;
   struct ip_tunnel_parm p;
   char devName[IFNAMSIZ];
   char ipAddr[IFNAMSIZ];

   memset(&devName, 0, sizeof(devName));
   memset(&ipAddr, 0, sizeof(ipAddr));

   strcat(devName, PREFIXNAME);
   strcat(devName, index);

   strcat(ipAddr, PREFIXADDR);
   strcat(ipAddr, index);

   printf("Device Name is %s Ip Address is  %s\n", devName, ipAddr);

   if (parseArgs(cmd, &p, devName, ipAddr) < 0)
      return -1;
   strncpy(ifr.ifr_name, "gre0", IFNAMSIZ);
   ifr.ifr_ifru.ifru_data = (void*)&p;
   fd = socket(AF_INET, SOCK_DGRAM, 0);
   err = ioctl(fd, cmd, &ifr);
   if (err)
      perror("ioctl");
   close(fd);
   return err;
}

static int deleteTunnel(const char *dev)
{
   struct ifreq ifr;
   int fd;
   int err;
   int cmd = SIOCDELTUNNEL;
   struct ip_tunnel_parm p;

   if (parseArgs(cmd, &p, dev, NULL) < 0)
      return -1;

   if (p.name[0])
      strncpy(ifr.ifr_name, p.name, IFNAMSIZ);
   else
      strncpy(ifr.ifr_name, "gre0", IFNAMSIZ);
   ifr.ifr_ifru.ifru_data = (void*)&p;
   fd = socket(AF_INET, SOCK_DGRAM, 0);
   err = ioctl(fd, SIOCDELTUNNEL, &ifr);
   if (err)
      perror("ioctl");
   close(fd);
   return err;
}

void removeColon(char *str) {
    char *src, *dst;
    for (src = dst = str; *src != '\0'; src++) {
        *dst = *src;
        if (*dst != ':') dst++;
    }
    *dst = '\0';
}

static int getTunnels()
{
   char name[IFNAMSIZ];
   unsigned long  rx_bytes, rx_packets, rx_errs, rx_drops,
   rx_fifo, rx_frame,
   tx_bytes, tx_packets, tx_errs, tx_drops,
   tx_fifo, tx_colls, tx_carrier, rx_multi;
   int type;
   struct ip_tunnel_parm p1;
   int i = 0;

   char buf[512];
   FILE *fp = fopen("/proc/net/dev", "r");
   if (fp == NULL) {
      perror("fopen");
      return -1;
   }

   fgets(buf, sizeof(buf), fp);
   fgets(buf, sizeof(buf), fp);

   i = 0;
   while (fgets(buf, sizeof(buf), fp) != NULL) {
      char *ptr;
      buf[sizeof(buf) - 1] = 0;
      if ((ptr = strchr(buf, ':')) == NULL ||
          (*ptr++ = 0, sscanf(buf, "%s", name) != 1)) {
         fprintf(stderr, "Wrong format of /proc/net/dev. Sorry.\n");
         return -1;
      }
      type = do_ioctl_get_iftype(name);
      if (type == -1) {
         fprintf(stderr, "Failed to get type of [%s]\n", name);
         continue;
      }
      if (type != ARPHRD_TUNNEL && type != ARPHRD_IPGRE && type != ARPHRD_SIT)
         continue;
      memset(&p1, 0, sizeof(p1));
      if (do_get_ioctl(name, &p1))
         continue;
      if (strstr(p1.name, PREFIXNAME)) {
         strncpy(myTunnels[i], p1.name, IFNAMSIZ);
         removeColon(myTunnels[i]);
         i++;
      }
   }
   return 0;
}

static int showTunnels()
{
   int err;
   struct ip_tunnel_parm p;
   int i = 0;
   memset(&p, 0, sizeof(p));
   printf("Tunnels are: \n");
   while (myTunnels[i][0] != 0) {
      printf("name: %s:", myTunnels[i]);
      printf("\n");
      i++;
   }
   return 0;
}

void deleteAll() {
   int i = 0;
   while (myTunnels[i][0] != 0) {
      deleteTunnel(myTunnels[i]);
      printf("deleting: %s:", myTunnels[i]);
      printf("\n");
      i++;
   }
}


int
read_event (int sockint)
{
   int status;
   int ret = 0;
   char buf[4096];
   struct iovec iov = { buf, sizeof buf };
   struct sockaddr_nl snl;
   struct msghdr msg = { (void *) &snl, sizeof snl, &iov, 1, NULL, 0, 0 };
   struct nlmsghdr *h;
   struct ifinfomsg *iface;
   int len;
   struct rtattr *attribute;

   status = recvmsg (sockint, &msg, 0);

   if (status < 0) {
      /* Socket non-blocking so bail out once we have read everything */
      if (errno == EWOULDBLOCK || errno == EAGAIN)
         return ret;
      /* Anything else is an error */
      printf ("read_netlink: Error recvmsg: %d\n", status);
      perror ("read_netlink: Error: ");
      return status;
   }

   if (status == 0) {
      printf ("read_netlink: EOF\n");
   }

   // We need to handle more than one message per 'recvmsg'
   for (h = (struct nlmsghdr *) buf; NLMSG_OK (h, (unsigned int) status);
            h = NLMSG_NEXT (h, status)) {
         //Finish reading 
         if (h->nlmsg_type == NLMSG_DONE)
            return ret;
         // Message is some kind of error 
         if (h->nlmsg_type == NLMSG_ERROR) {
            printf ("read_netlink: Message is an error - decode TBD\n");
            return -1;        // Error
         }
         if (h->nlmsg_type == RTM_NEWLINK) {
            iface = NLMSG_DATA (h);
            len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));
            /* loop over all attributes for the NEWLINK message */
            for (attribute = IFLA_RTA(iface); RTA_OK(attribute, len); 
                  attribute = RTA_NEXT(attribute, len)) {
               switch(attribute->rta_type) {
                  case IFLA_IFNAME:
                     printf("\nTunnel added %d : %s\n", iface->ifi_index, 
                        (char *) RTA_DATA(attribute));
                     break;
                  default:
                     break;
               }
            }
         }
      }
  return ret;
}

void listenTunnels(int ifIndex) {
   fd_set rfds, wfds;
   struct timeval tv;
   int retval;
   struct sockaddr_nl addr;
   int nl_socket;

   if ( (nl_socket = socket (AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0 ) {
      perror("Socket Open Error!");
      exit (1);
   }
   memset ((void *) &addr, 0, sizeof (addr));
   addr.nl_family = AF_NETLINK;
   addr.nl_pid = getpid ();
   addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
   //  addr.nl_groups = RTMGRP_LINK;

   if (bind (nl_socket, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
      perror("Socket bind failed!");
      exit (1);
   }
   if (ifIndex) {
      char digits[5];
      long int offsetdata;
      ifIndex = 96;
      snprintf(digits, 12,"%d",ifIndex);
      printf("ifindex is %s \n", digits );
      printf("ifindex is %d \n", digits[0] );
      printf("ifindex is %d \n", digits[1] );
      
      offsetdata = 216; //sk->data

      struct sock_filter code[] = {
        { 0x20,  0,  0, 0xfffff00c },
        { 0x01,  0,  0, 0x00000010 },
        { 0x50,  0,  0, 0x00000017 },
        { 0x15,  0,  3, digits[0] },
        { 0x50,  0,  0, 0x00000018 },
        { 0x15,  0,  0, digits[1] },
        { 0x06,  0,  0, 0xffffffff },
        { 0x06,  0,  0, 0000000000 },
      };

      #define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

      struct sock_fprog bpf = {
            .len = ARRAY_SIZE(code),
            .filter = code,
      };

      retval = setsockopt( nl_socket, SOL_SOCKET, SO_ATTACH_FILTER,
                           &bpf, sizeof(bpf));
      perror("setsockopt");
      //printf("strerr %s, err %d \n", strerror(errno), errno);
   }
   while (1) {
      FD_ZERO (&rfds);
      FD_CLR (nl_socket, &rfds);
      FD_SET (nl_socket, &rfds);

      tv.tv_sec = 10;
      tv.tv_usec = 0;

      retval = select (FD_SETSIZE, &rfds, NULL, NULL, &tv);
      if (retval == -1)
         printf ("Error select() \n");
      else if (retval) {
         //printf ("Event recieved >> ");
         read_event (nl_socket);
      }
   }
}

void main(int argc, char *argv[]) {
   long index;
   memset(&myTunnels, 0, sizeof(myTunnels));
   getTunnels();
   if (!strcmp(argv[1], "show") ) {
   showTunnels();
   }
      if (!strcmp(argv[1], "del") ) {
      deleteAll();
   }
   if (!strcmp(argv[1], "add") ) {
      addTunnel(argv[2]);
   }
   if (!strcmp(argv[1], "listen") ) {
      listenTunnels(0);
   }
   if (!strcmp(argv[1], "mul") ) {
      deleteTunnel("pri96");
      deleteTunnel("pri87");
      addTunnel("96");
      addTunnel("87");
   }
   if (!strcmp(argv[1], "filter") ) {
      index = strtol(argv[2], NULL, 10);
      listenTunnels(index);
   }
}

