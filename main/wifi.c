#include "wifi.h"
#include "NinePea.h"
#include "esp_pthread.h"
#include <pthread.h>

#define DEFAULT_SCAN_LIST_SIZE 30

static esp_netif_t *sta_netif = NULL;
pthread_mutex_t scanmutex = PTHREAD_MUTEX_INITIALIZER;
static uint16_t ap_count = 0;

Wnode *wns;

static char *essid;

static char Sconn[] = "connecting";
static char Sauth[] = "authenticated";
static char Sneedauth[] = "need authentication";
static char Sunauth[] = "unauthenticated";

static char Sassoc[] = "associated";
static char Sunassoc[] = "unassociated";
static char Sblocked[] = "blocked";	/* no keys negotiated. only pass EAPOL frames */

char*
status(void)
{
	return Sneedauth;
}

unsigned long
inpkts(void)
{
	return 0;
}

int
linkstatus(void)
{
	return 0;
}

unsigned long
outpkts(void)
{
	return 0;
}

int
rssi(void)
{
	return 0;
}

char*
get_essid(void)
{
	return essid? essid: "";
}

char*
bssid(void)
{
	return "";
}

int
channel(void)
{
	return 0;
}

void
set_essid(char *in)
{
	essid = strdup(in);
}

void*
scan_func(void *p)
{
	uint16_t number = DEFAULT_SCAN_LIST_SIZE;
	wifi_ap_record_t ap_info[DEFAULT_SCAN_LIST_SIZE];
	int i;
	struct timespec ts;
	pthread_mutex_t sleepmutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t sleepcond = PTHREAD_COND_INITIALIZER;
	struct timeval tv;
	unsigned long now;
	wifi_scan_config_t cfg = {
		.ssid = 0,
		.bssid = 0,
		.channel = 0,
		.show_hidden = true
	};

	pthread_mutex_init(&sleepmutex, NULL);
	pthread_cond_init(&sleepcond, NULL);

	for(;;) {
		memset(ap_info, 0, sizeof(ap_info));

		ESP_ERROR_CHECK(esp_wifi_scan_start(&cfg, true));
		ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, ap_info));
		ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));

		gettimeofday(&tv, NULL);
		now = tv.tv_sec * 1000LL + (tv.tv_usec / 1000LL);

		for (i = 0; i < DEFAULT_SCAN_LIST_SIZE && i < ap_count; i++) {
			sprintf(wns[i].ssid, "%s", ap_info[i].ssid);
			memcpy(wns[i].bssid, ap_info[i].bssid, 6);
			wns[i].lastseen = now;
			wns[i].channel = ap_info[i].primary;
		}

		pthread_mutex_lock(&sleepmutex);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 5;
		pthread_cond_timedwait(&sleepcond, &sleepmutex, &ts);
		pthread_mutex_unlock(&sleepmutex);
	}

	return NULL;
}

void
init_wifi(void)
{
	pthread_t t1;

	ESP_ERROR_CHECK(nvs_flash_init());

	ESP_ERROR_CHECK(esp_netif_init());
	sta_netif = esp_netif_create_default_wifi_sta();
	assert(sta_netif != NULL);

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_start());

	wns = calloc(DEFAULT_SCAN_LIST_SIZE, sizeof(Wnode));

	pthread_create(&t1, NULL, scan_func, NULL);
}

void
mac2str(char *str, uint8_t *mac)
{
	sprintf(str, "%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void
get_mac_address(char *str)
{
	uint8_t mac[6];

	ESP_ERROR_CHECK(esp_efuse_mac_get_default(mac));

	mac2str(str, mac);
}

unsigned long
read_stats(char *str)
{
	char mac[13];
	unsigned long ret;

	get_mac_address(mac);

	ret = sprintf(str, "in: %lu\n"
			"link: %d\n"
			"out: %lu\n"
			"crc errs: %d\n"
			"overflows: %d\n"
			"soft overflows: %d\n"
			"framing errs: %d\n"
			"buffer errs: %d\n"
			"output errs: %d\n"
			"prom: %d\n"
			"mbps: %d\n"
			"addr: %s\n",
			inpkts(), linkstatus(), outpkts(),
			0, 0, 0, 0, 0, 0, 0,
			2, mac);

	return ret;
}

unsigned long
read_ifstats(char *str)
{
	unsigned long ret;
	int i;
	char mac[13];
	struct timeval tv;
	unsigned long now;

	ret = sprintf(str, "Signal: %d\n"
			"essid: %s\n"
			"bssid: %s\n"
			"status: %s\n"
			"channel: %.2d\n",
			rssi(), get_essid(), bssid(), status(), channel());

	gettimeofday(&tv, NULL);
	now = tv.tv_sec * 1000LL + (tv.tv_usec / 1000LL);

	for (i = 0; i < ap_count && i < DEFAULT_SCAN_LIST_SIZE; i++) {
		mac2str(mac, wns[i].bssid);
		ret += snprintf(&str[ret], MAX_IO - ret, "node: %s %.4x %-11ld %.2d %s\n", mac, wns[i].cap, now - wns[i].lastseen, wns[i].channel, wns[i].ssid);
	}

	return ret;
}

