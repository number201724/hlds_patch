#ifndef __HL_NETCHAN_H
#define __HL_NETCHAN_H

typedef enum
{
	NS_CLIENT,
	NS_SERVER
} netsrc_t;

#define FSB_ALLOWOVERFLOW (1<<0)
#define FSB_OVERFLOWED (1<<1)

typedef struct sizebuf_s
{
	char *name;
	int flags;
	byte *data;
	int maxsize;
	int cursize;
}
sizebuf_t;

enum netadrtype_t {
  NA_UNUSED = 0x0,
  NA_LOOPBACK = 0x1,
  NA_BROADCAST = 0x2,
  NA_IP = 0x3,
  NA_IPX = 0x4,
  NA_BROADCAST_IPX = 0x5,
};

struct netadr_t {
  netadrtype_t type;
  char ip_addr[4];
  char ipx_addr[10];
  unsigned short port;
};

// Network Connection Channel
typedef struct
{
	// NS_SERVER or NS_CLIENT, depending on channel.
	netsrc_t    sock;               

	// Address this channel is talking to.
	netadr_t	remote_address;  

	// For timeouts.  Time last message was received.
	float		last_received;		
	// Time when channel was connected.
	float       connect_time;       

	// Bandwidth choke
	// Bytes per second
	double		rate;				
	// If realtime > cleartime, free to send next packet
	double		cleartime;			

	void* NET_DONNT_USE; // 不要使用省略以下定义。。详细看 （net.h）
	// ...
	// ...

}netchan_t;

/*
// Network Connection Channel
typedef struct
{
	// NS_SERVER or NS_CLIENT, depending on channel.
	netsrc_t    sock;               

	// Address this channel is talking to.
	netadr_t	remote_address;  
	
	// For timeouts.  Time last message was received.
	float		last_received;		
	// Time when channel was connected.
	float       connect_time;       

	// Bandwidth choke
	// Bytes per second
	double		rate;				
	// If realtime > cleartime, free to send next packet
	double		cleartime;			

	// Sequencing variables
	//
	// Increasing count of sequence numbers 
	int			incoming_sequence;              
	// # of last outgoing message that has been ack'd.
	int			incoming_acknowledged;          
	// Toggles T/F as reliable messages are received.
	int			incoming_reliable_acknowledged;	
	// single bit, maintained local
	int			incoming_reliable_sequence;	    
	// Message we are sending to remote
	int			outgoing_sequence;              
	// Whether the message contains reliable payload, single bit
	int			reliable_sequence;			    
	// Outgoing sequence number of last send that had reliable data
	int			last_reliable_sequence;		    

	// Staging and holding areas
	bf_write	message;
	byte		message_buf[NET_MAX_PAYLOAD];

	// Reliable message buffer.  We keep adding to it until reliable is acknowledged.  Then we clear it.
	int			reliable_length;
	byte		reliable_buf[NET_MAX_PAYLOAD];	// unacked reliable message

	// Waiting list of buffered fragments to go onto queue.
	// Multiple outgoing buffers can be queued in succession
	fragbufwaiting_t *waitlist[ MAX_STREAMS ]; 

	// Is reliable waiting buf a fragment?
	int				reliable_fragment[ MAX_STREAMS ];          
	// Buffer id for each waiting fragment
	unsigned int	reliable_fragid[ MAX_STREAMS ];

	// The current fragment being set
	fragbuf_t	*fragbufs[ MAX_STREAMS ];
	// The total number of fragments in this stream
	int			fragbufcount[ MAX_STREAMS ];

	// Position in outgoing buffer where frag data starts
	short		frag_startpos[ MAX_STREAMS ];
	// Length of frag data in the buffer
	short		frag_length[ MAX_STREAMS ];

	// Incoming fragments are stored here
	fragbuf_t	*incomingbufs[ MAX_STREAMS ];
	// Set to true when incoming data is ready
	qboolean	incomingready[ MAX_STREAMS ];

	// Only referenced by the FRAG_FILE_STREAM component
	// Name of file being downloaded
	char		incomingfilename[ MAX_OSPATH ];

	// Incoming and outgoing flow metrics
	flow_t flow[ MAX_FLOWS ];  
} netchan_t;
*/

#endif