#ifndef INC_HLMASTERH
#define INC_HLMASTERH

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

/*
Master server protocols
The first byte is the command code.
Followed by a \n, then any other parameters, each followed by a \n.
An empty parameter is acceptable.
*/

#define LAUNCHERONLY
#include "protocol.h"
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

#define	MAX_CHALLENGES	(32)  // 4K of challenges should be plenty
#define	SERVER_TIMEOUT	(60*15)   // Server's time out after 15 minutes w/o a heartbeat
#define MIN_SV_TIMEOUT_INTERVAL (60) // Once every minute is fast enough

typedef struct sockaddr_in	netadr_t;
typedef unsigned char byte;

// MAX_CHALLENGES is made large to prevent a denial
//  of service attack that could cycle all of them
//  out before legitimate users connected
//-----------------------------------------------------------------------------
// Purpose: Define master server challenge response
//-----------------------------------------------------------------------------
typedef struct
{
	// Address where challenge value was sent to. 
	netadr_t    adr;       
	// To connect, adr IP address must respond with this #
	int			challenge; 
	// # is valid for only a short duration.
	int			time;      
} challenge_t;

//-----------------------------------------------------------------------------
// Purpose: Represents statistics for a mod
//-----------------------------------------------------------------------------
typedef struct modsv_s
{
	// Next mod in chain
	struct modsv_s	*next;

	// Name of the mod
	char			gamedir[ 64 ];
	
	// Current number of players and servers
	int				ip_players;
	int				ip_servers;
	int				ip_bots;
	int				ip_bots_servers;
	int				lan_players;
	int				lan_servers;
	int				lan_bots;
	int				lan_bots_servers;
	int				proxy_servers;
	int				proxy_players;
} modsv_t;

#define MAX_SINFO 2048

#define VALUE_LENGTH 64
typedef struct string_criteria_s
{
	int		checksum;
	int		length;
	char	value[ VALUE_LENGTH ];
} string_criteria_t;

//-----------------------------------------------------------------------------
// Purpose: Represents a game server
//-----------------------------------------------------------------------------
typedef struct sv_s
{
	// Next server in chain
	struct	sv_s	*next;
	// IP address and port of the server
	netadr_t		address;
	// For master server list, is this an "old" server
	int				isoldserver;     
	// Is a local area network server (not in returned lists to clients)
	int				islan;
	// Time of last heartbeat from server
	int				time;
	// Unique id of the server, for batch requesting servers
	int				uniqueid;
	int				region;

	// Queryable data
	
	// Spectator proxy support
	int				isproxy;
	// Is a proxy target ( count of proxies connect to this regular server )
	int				isProxyTarget;
	// If watching server, this is the address of the server proxy is watching
	string_criteria_t proxyTarget;

	// Current # of players
	int				players;
	// Max # of players
	int				max;
	// # of fake players
	int				bots;
	// Mod this server is playing
	string_criteria_t	gamedir;
	// Map this server is playing
	string_criteria_t	map;
	// OS of the server
	char			os[ 2 ];
	// Is the server running a password protected game
	int				password;
	// Is the server a dedicated server
	int				dedicated;
	// Is the server a secure server using mobile anticheat code
	int				secure;
	// Raw server info from heartbeat packet
	char			info[ MAX_SINFO ];
	int				info_length;
} sv_t;


#define PEER_HEARTBEAT 1
#define PEER_SHUTDOWN  2
#define PEER_HEARTBEAT2 3

#define SERVER_HASH_SIZE 2048

#define MOD_HASH_SIZE 53

#define REGION_ANY 255
#define REGION_US_EAST 0
#define REGION_US_WEST 1
#define REGION_NORTH_AMERAICA 0
#define REGION_SOUTH_AMERAICA 2
#define REGION_EUROPE 3
#define REGION_ASIA 4
#define REGION_AUSTRALIA 5
#define REGION_MIDDLE_EAST 6
#define REGION_AFRICA 7



/////////////////////////////////////////////////////////////////////////////
// CHLMaster dialog
class CHLMaster
{
// Construction
public:
	void Packet_RequestsBatch( void );
	void Packet_WONMonitor( void );

	int VerToInt( const char *pszVersion );
	BOOL IsLessThan( const char *pszUser, const char *pszServer );
	BOOL IsEqualTo( const char *pszStringA, const char *pszStringB );
	void ParseVersion( void );

	CHLMaster( int nMasterPort, BOOL bGenerateLogs, const char *strLocalIPAddress );	// standard constructor
	~CHLMaster();

	BOOL Init(void);

// Initialization and shutdown
	void Master_Init();
	void NET_Init();
	void NET_GetLocalAddress (void);

	void CheckForNewLogfile();
	void OpenNewLogfile();

// Routines for handling serving out titan/auth/and master server lists
	sv_t *AddServer( sv_t **pList, netadr_t *adr );
	void ParseServers();
	sv_t *FindServerByAddress (netadr_t *adr);
	void FreeServers();

	void GenerateFakeServers( void );

// Mod info
	modsv_t *FindMod( const char *pszGameDir );
	void FreeMods( void );
	void ListMods( void );
	int SizeMod( modsv_t *p );
	int HashMod( const char *pszGameDir );
	void AdjustCounts( void );

// Query Responses
	void ServiceMessages();

	void GetPacketCommand (void);
	void PacketCommand();

	void Peer_Heartbeat( sv_t *sv );
	void Peer_Heartbeat2( sv_t *sv );
	void Peer_Shutdown( sv_t *sv );
	void Packet_GetPeerMessage( void );
	void Peer_GetHeartbeat( void );
	void Peer_GetHeartbeat2( void );
	void Peer_GetShutdown( void );

	void Packet_GetChallenge (void);
	void Packet_GetMasterServers ();
	void Packet_Heartbeat();
	void Packet_Heartbeat2();
	void Packet_Heartbeat3();
	void Packet_Shutdown();
	void Packet_QueryVAC();
	void Packet_GetServers();
	void Packet_GetBatch();
	void Packet_GetBatch2();
	void Packet_GetModBatch();
	void Packet_GetModBatch2();
	void Packet_GetModBatch3();
	void Packet_Ping();
	void Packet_Motd();
	void Packet_InfoDetailed();
	void Packet_InfoSource();
	void Packet_ServerBatch();
	void Nack (char *comment, ...);

	void Packet_GetBatch_Responder( int region, int truenextid, struct search_criteria_s *criteria, netadr_t host );
	inline int ServerPassesCriteria( sv_t *server, struct search_criteria_s *criteria );

	BOOL PacketFilter();
	void RejectConnection(netadr_t *adr, const char *pszMessage);
	void RequestRestart(netadr_t *adr);

// Utils
	unsigned char Nibble( char c );
	void HexConvert( char *pszInput, int nInputLength, unsigned char *pOutput );
	
	BOOL MSG_ReadData(int nLength, void *nBuffer);
	char *MSG_ReadString (void);
	unsigned char MSG_ReadByte( void );
	unsigned short MSG_ReadShort( void );
	unsigned int MSG_ReadLong( void );

	void Packet_Printf( int& curpos, const char *fmt, ... );
	void Sys_SendPacket (netadr_t *to, byte *data, int len);

	void Sys_Error (const char *string, ...);
	void UTIL_VPrintf (const char *msg, ...);  // Print if we are showing traffic:  i.e. verbose
	void UTIL_Printf (const char *msg, ...);   // Print message unconditionally

// UI
	void MoveControls();
	void UpdateCount();
	void UpdatePeerServers();
	
	int RunLoop();

	float	GetOutBytesProcessed();
	int		GetInTransactions();
	float	GetBytesProcessed();
	
	void	ResetTimer();
	double	GetStartTime();

	void	TimeoutServers();

	int		CheckChallenge( int challenge, netadr_t *adr );

	BOOL	m_bShowTraffic;
	BOOL	m_bAllowOldProtocols;
	BOOL		m_bShowPackets;
// Data
protected:
	fd_set		fdset;				// Master server file descriptor set.
	int			net_socket;			// Master server socket
	int			net_hostport;		// Port # this master is listening on
	netadr_t	net_local_adr;		// IP address of this master
	netadr_t	packet_from;		// Address of message we just received
	ssize_t			packet_length;		// Amount of data we received

	int			m_curtime;

	char		m_strLocalIPAddress[64];	// Can be provided on cmd line if on dual nic machine
	
// Server lists
	sv_t		*authservers;		// WON auth servers in use.
	sv_t        *titanservers;		// WON directory servers in use
	sv_t        *masterservers;		// Other master servers in use.
	sv_t		*servers[ SERVER_HASH_SIZE ];			// Game servers being tracked by this master.
	sv_t		*bannedips;			// ip addresses that are banned
	sv_t		*peerservers;		// Other master servers in use.

	modsv_t     *mods[ MOD_HASH_SIZE ];

	challenge_t	challenges[256][MAX_CHALLENGES];	// to prevent spoofed IPs from connecting

// Send/Receive buffers
	char		reply[1400];		// Outgoing buffer, limit to max UDP size
	byte		packet_data[65536]; // Incoming data
	int			msg_readcount;      // # of bytes of message we have parsed

	char		m_statTime[64];
	char		m_statInTransactions[64];
	char		m_statLoad[64];
	char		m_statLoadOut[64];


	int			m_nUniqueID;        // Incrementing server ID counter for batch query
	
// Profiling vars ( per cycle )
	float		m_fCycleTime;       // Time of each cycle ( e.g., 1 min ).

	int			m_nInTransactions;  // # of requests we've parsed
	float		m_fBytesSent;       // # of outgoing bytes
	float		m_fBytesProcessed;  // # of incoming bytes
	double		m_tStartTime;       // Cycle Start time

// Log File
	FILE		*logfile;
	int			m_nCurrentDay;
	BOOL		m_bGenerateLogs;

private:
	void FreeGameServers( void );
	int HashServer( netadr_t *address );

	char m_szHLVersion[32];
	char m_szCSVersion[32];
	char m_szTFCVersion[32];
	char m_szDMCVersion[32];
	char m_szOpForVersion[32];
	char m_szRicochetVersion[32];
	char m_szDODVersion[32];

	int  m_nUsers;
	int  m_nServerCount;
	int  m_nBotCount;

	int	 m_nLanServerCount;
	int	 m_nLanUsers;
	int  m_nLanBotCount;



};


#endif // INC_HLMASTERH
