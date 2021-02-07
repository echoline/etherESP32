#include "nvs_flash.h"
#include "esp_wifi.h"
#include "NinePea.h"

#define uchar unsigned char
#define uvlong unsigned long long

#define Eaddrlen 6
#define WIFIHDRSIZE (2+2+3*6+2)

typedef struct Wkey Wkey;
typedef struct Wnode Wnode;
typedef struct Wifipkt Wifipkt;

/* cipher */
enum {
	TKIP	= 1,
	CCMP	= 2,
};

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

struct Wifipkt
{
	uchar	fc[2];
	uchar	dur[2];
	uchar	a1[Eaddrlen];
	uchar	a2[Eaddrlen];
	uchar	a3[Eaddrlen];
	uchar	seq[2];
	uchar	a4[Eaddrlen];
};


void init_wifi(void);
void get_mac_address(char*);
unsigned long read_stats(char*);
unsigned long read_ifstats(char*);
unsigned long read_data(char*, int);
unsigned long write_data(uchar*, unsigned long, int);
unsigned long read_log(char*, unsigned long, unsigned long);
void set_essid(char*);
void set_brsne(char*);
void set_key_str(char*);

