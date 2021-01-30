#include "wifi.h"

#define DEFAULT_SCAN_LIST_SIZE 64

static uint16_t ap_count;

static Wnode *wns;
static Wnode *bss;
static uint8_t cur_channel;
static char *essid;
static char *brsne;
static int rssi;
static char *log;

static char Sconn[] = "connecting";
static char Sauth[] = "authenticated";
static char Sneedauth[] = "need authentication";
static char Sunauth[] = "unauthenticated";

static char Sassoc[] = "associated";
static char Sunassoc[] = "unassociated";
static char Sblocked[] = "blocked";	/* no keys negotiated. only pass EAPOL frames */

static char *ciphers[] = {
	[0]	"clear",
	[TKIP]	"tkip",
	[CCMP]	"ccmp",
};

void
mac2str(char *str, uint8_t *mac)
{
	sprintf(str, "%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

char*
get_status(void)
{
	if (bss == NULL || bss->status == NULL)
		return "";
	return bss->status;
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
get_rssi(void)
{
	return rssi;
}

char*
get_essid(void)
{
	return essid? essid: "";
}

char*
get_bssid(void)
{
	static char ret[13];
	if (bss != NULL)
		mac2str(ret, bss->bssid);
	else
		sprintf(ret, "ffffffffffff");
	return ret;
}

void
set_essid(char *in)
{
	Wifipkt *w;
	uint8_t mac[6];
	uint8_t *buf;
	uint8_t *p;
	int n;

	ESP_ERROR_CHECK(esp_efuse_mac_get_default(mac));

	if (essid != NULL)
		free(essid);
	essid = strndup(in, 32);

	n = strlen(essid);

	buf = calloc(1, WIFIHDRSIZE+512);
	w = (Wifipkt*)buf;
	w->fc[0] = 0x40;
	w->fc[1] = 0x00;
	memset(w->a1, '\xFF', 6);
	memcpy(w->a2, mac, 6);
	memset(w->a3, '\xFF', 6);
	p = buf + WIFIHDRSIZE;
	*p++ = 0; // essid
	*p++ = n;
	memcpy(p, essid, n);
	p += n;
	*p++ = 0x01;
	*p++ = 0x01;
	*p++ = 0x84;	//Supported Rates: 2(B)

	while(bss == NULL) {
		ESP_ERROR_CHECK(esp_wifi_set_channel(cur_channel, WIFI_SECOND_CHAN_NONE));
		ESP_ERROR_CHECK(esp_wifi_80211_tx(ESP_IF_WIFI_STA, buf, p-buf, true));
		vTaskDelay(200 / portTICK_PERIOD_MS);
		if (bss == NULL)
			cur_channel = 1 + ((cur_channel+4) % 13);
	}

	free(buf);
}

void
set_brsne(char *in)
{
	if (brsne != NULL)
		free(brsne);
	brsne = strdup(in);
	if (bss != NULL)
		bss->status = Sconn;
}

void
sendauth(void)
{
	Wifipkt *w;
	uint8_t mac[6];
	uint8_t *buf;
	uint8_t *p;
	esp_err_t r;
	int l;

	ESP_ERROR_CHECK(esp_efuse_mac_get_default(mac));

	buf = calloc(1, WIFIHDRSIZE+3*2);
	w = (Wifipkt*)buf;
	w->fc[0] = 0xB0;
	w->fc[1] = 0x00;
	memmove(w->a1, bss->bssid, Eaddrlen);
	memmove(w->a2, mac, Eaddrlen);
	memmove(w->a3, bss->bssid, Eaddrlen);
	p = buf + WIFIHDRSIZE;
	*p++ = 0;
	*p++ = 0;
	*p++ = 1;
	*p++ = 0;
	*p++ = 0;
	*p++ = 0;

	r = esp_wifi_80211_tx(ESP_IF_WIFI_STA, buf, p-buf, true);
	if (r != ESP_OK) {
		l = strlen(log);
		log = realloc(log, l + 64);
		sprintf(&log[l], "sendauth: %s\n", esp_err_to_name(r));
	}
	free(buf);
}

static void
wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
	wifi_promiscuous_pkt_t *packet = (wifi_promiscuous_pkt_t*)buf;
	uint8_t *p = packet->payload;
	Wifipkt *w;
	int i, l, rsnset = 0;
	uint8_t mac[6];
	struct timeval tv;
	unsigned long now;
	char str[13];

	gettimeofday(&tv, NULL);
	now = tv.tv_sec * 1000LL + (tv.tv_usec / 1000LL);

	ESP_ERROR_CHECK(esp_efuse_mac_get_default(mac));

	switch (type) {
	case WIFI_PKT_MGMT:
		switch(p[0] & 0xF0) {
		case 0x50: // probe response
			w = (Wifipkt*)p;
			if (memcmp(mac, w->a1, 6) == 0) {
				rssi = packet->rx_ctrl.rssi;
				for (i = 0; i < ap_count && i < DEFAULT_SCAN_LIST_SIZE; i++) {
					if (memcmp(wns[i].bssid, w->a3, 6) == 0)
						break;
				}
				if (i < DEFAULT_SCAN_LIST_SIZE) {
					if (i == ap_count)
						ap_count++;
					memcpy(wns[i].bssid, w->a3, 6);
					wns[i].lastseen = now;
					wns[i].channel = cur_channel;
					memcpy(wns[i].ssid, essid, strlen(essid));
				}
			}
			break;
		case 0x80: // beacon
			w = (Wifipkt*)p;
			for (i = 0; i < ap_count && i < DEFAULT_SCAN_LIST_SIZE; i++) {
				if (memcmp(wns[i].bssid, w->a3, 6) == 0)
					break;
			}
			if (i < DEFAULT_SCAN_LIST_SIZE) {
				if (i == ap_count)
					ap_count++;
				memcpy(wns[i].bssid, w->a3, 6);
				wns[i].lastseen = now;
				wns[i].channel = cur_channel;
				wns[i].cap = (p[WIFIHDRSIZE+11] << 8) | p[WIFIHDRSIZE+10];
				l = p[WIFIHDRSIZE+13];
				if (l > 32)
					l = 32;
				memcpy(wns[i].ssid, &p[WIFIHDRSIZE+14], l);
				l = WIFIHDRSIZE + 14 + p[WIFIHDRSIZE+13];
				while (l < (packet->rx_ctrl.sig_len-4)) {
					switch(p[l]) {
					case 1: // rates
					case 50:
						l++;
						l += p[l] + 1;
						break;
					case 3:
						l++;
						if (p[l] != 0)
							if (p[l+1] != wns[i].channel)
								wns[i].channel = p[l+1];
						l += p[l] + 1;
						break;
					case 5:
						l++;
						l += p[l] + 1;
						break;
					case 221: // ???
						l++;
						l += p[l] + 1;
						if (rsnset)
							break;
					case 48:
						wns[i].brsnelen = p[l+1] + 2;
						memcpy(wns[i].brsne, &p[l], wns[i].brsnelen);
						rsnset = 1;
						l += wns[i].brsnelen;
						break;
					default:
						l++;
						l += p[l] + 1;
						break;
					}
				}
				if (bss == NULL && essid != NULL) {
					if (strcmp(essid, wns[i].ssid) == 0) {
						bss = &wns[i];
						bss->status = Sconn;
						sendauth();
					}
				}
			}
			break;
		default:
			w = (Wifipkt*)p;
			mac2str(str, w->a3);
			l = strlen(log);
			log = realloc(log, l + 32);
			sprintf(&log[l], "%02x:%s\n", p[0], str);
			break;
		}
		break;
	default:
		break;
	}
}

void
init_wifi(void)
{
	wifi_second_chan_t chan;
	esp_netif_t *sta;

	log = calloc(1, sizeof(char));

	ESP_ERROR_CHECK(nvs_flash_init());

	ESP_ERROR_CHECK(esp_netif_init());
	sta = esp_netif_create_default_wifi_sta();
	assert(sta != NULL);
	ESP_ERROR_CHECK(esp_netif_attach_wifi_station(sta));
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

	ESP_ERROR_CHECK(esp_wifi_start());

	ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

	ESP_ERROR_CHECK(esp_wifi_get_channel(&cur_channel, &chan));

	ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
	ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_cb));

	wns = calloc(DEFAULT_SCAN_LIST_SIZE, sizeof(Wnode));
	ap_count = 0;
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
	Wkey *k;

	ret = sprintf(str, "Signal: %d\n"
			"essid: %s\n"
			"bssid: %s\n",
			get_rssi(), get_essid(), get_bssid());

	if (bss != NULL) {
		ret += snprintf(&str[ret], MAX_IO - ret,
			"status: %s\nchannel: %d\n",
			get_status(), bss->channel);

		for (i = 0; i < 5; i++)
			if ((k = bss->rxkey[i]) != NULL)
				ret += snprintf(&str[ret], MAX_IO - ret,
					"rxkey%d: %s:[%d]\n", i,
					ciphers[k->cipher], k->len);

		k = bss->txkey[0];
		if (k != NULL)
			ret += snprintf(&str[ret], MAX_IO - ret,
				"txkey%d: %s:[%d]\n", 0,
				ciphers[k->cipher], k->len);

		if (bss->brsnelen > 0) {
			ret += snprintf(&str[ret], MAX_IO - ret, "brsne: ");
			for (i = 0; i < bss->brsnelen; i++)
				ret += snprintf(&str[ret], MAX_IO - ret,
					"%.2X", bss->brsne[i]);
			ret += snprintf(&str[ret], MAX_IO - ret, "\n");
		}
	}

	gettimeofday(&tv, NULL);
	now = tv.tv_sec * 1000LL + (tv.tv_usec / 1000LL);

	for (i = 0; i < ap_count && i < DEFAULT_SCAN_LIST_SIZE; i++) {
		mac2str(mac, wns[i].bssid);
		ret += snprintf(&str[ret], MAX_IO - ret, "node: %s %.4x %-11ld %.2d %s\n", mac, wns[i].cap, now - wns[i].lastseen, wns[i].channel, wns[i].ssid);
	}

	return ret;
}

unsigned long
read_data(char *str, int type)
{
	uint8_t mac[6];
	uint16_t Keydescrlen = 1+2+2+8+32+16+8+8+16+2;

	if (type == 0x888e && bss != NULL) {
		ESP_ERROR_CHECK(esp_efuse_mac_get_default(mac));
		memcpy(str, mac, 6);
		memcpy(&str[6], bss->bssid, 6);
		memcpy(&str[12], "\x88\x8e", 2);
		str[14] = 0x02; // ???
		str[15] = 0x03;
		str[16] = (Keydescrlen >> 8) & 0xFF;
		str[17] = Keydescrlen & 0xFF;
		memset(&str[18], '\0', Keydescrlen); // TODO eapol data :(
		return 18 + Keydescrlen;
	}
	return 0;
}

unsigned long
read_log(char *out, unsigned long count, unsigned long offset)
{
	return snprintf(out, count, "%s", &log[offset]);
}
