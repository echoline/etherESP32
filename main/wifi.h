#include "nvs_flash.h"
#include "esp_wifi.h"

#define uchar unsigned char
#define uvlong unsigned long long

typedef struct Wkey Wkey;
typedef struct Wnode Wnode;

struct Wkey
{
	int		cipher;
	int		len;
	uvlong		tsc;
	uchar		key[];
};

struct Wnode
{
	uchar	bssid[6];
	char	ssid[34];

	char	*status;

	int	rsnelen;
	uchar	rsne[258];
	Wkey	*txkey[1];
	Wkey	*rxkey[5];

	int	aid;		/* association id */
	ulong	lastsend;
	ulong	lastseen;

	uchar	*minrate;	/* pointers into wifi->rates */
	uchar	*maxrate;
	uchar	*actrate;

	ulong	validrates;	/* bitmap on wifi->rates */
	ulong	basicrates;

	ulong	txcount;	/* statistics for rate adaption */
	ulong	txerror;

	/* stuff from beacon */
	uvlong	rs;
	uvlong	ts;
	uchar	dtimcount;
	uchar	dtimperiod;
	int	ival;
	int	cap;
	int	channel;
	int	brsnelen;
	uchar	brsne[258];
};

void init_wifi(void);
void get_mac_address(char*);
unsigned long read_stats(char*);
unsigned long read_ifstats(char*);
void set_essid(char*);

