#include "wifi.h"
#include "esp_log.h"
#include "esp_private/wifi.h"

#define DEFAULT_SCAN_LIST_SIZE 64

static uint16_t ap_count;

uint8_t *etherESP32_eapol_data;
uint32_t etherESP32_eapol_len;
uint8_t etherESP32_eapol_state;

static Wnode *wns;
static Wnode *bss;
static uint8_t cur_channel;
static char *essid;
static int rssi;

extern char *log_etherESP32;

static char Sconn[] = "connecting";
static char Sauth[] = "authenticated";
static char Sneedauth[] = "need authentication";
static char Sunauth[] = "unauthenticated";

static char Sassoc[] = "associated";
static char Sunassoc[] = "unassociated";
static char Sblocked[] = "blocked";	/* no keys negotiated. only pass EAPOL frames */

typedef struct eth_pkt eth_pkt;
struct eth_pkt {
	uint8_t *msg;
	int len;
	eth_pkt *next;
};

static eth_pkt *eth800;
static eth_pkt *eth806;
static eth_pkt *eth86dd;
uint8_t read800;
uint8_t read806;
uint8_t read86dd;
SemaphoreHandle_t mutex800 = NULL;
SemaphoreHandle_t mutex806 = NULL;
SemaphoreHandle_t mutex86dd = NULL;

static char *ciphers[] = {
	[0]	"clear",
	[TKIP]	"tkip",
	[CCMP]	"ccmp",
};

int
hextob(char *s, char **sp, uint8_t *b, int n)
{
	int r;

	n <<= 1;
	for(r = 0; r < n && *s; s++){
		*b <<= 4;
		if(*s >= '0' && *s <= '9')
			*b |= (*s - '0');
		else if(*s >= 'a' && *s <= 'f')
			*b |= 10+(*s - 'a');
		else if(*s >= 'A' && *s <= 'F')
			*b |= 10+(*s - 'A');
		else break;
		if((++r & 1) == 0)
			b++;
	}
	if(sp != NULL)
		*sp = s;
	return r >> 1;
}

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
	if (bss != NULL && (bss->status == Sassoc || bss->status == Sblocked))
		return 1;
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
sendbeacon(void)
{
	Wifipkt *w;
	uint8_t mac[6];
	uint8_t *buf;
	uint8_t *p;
	int n;

	ESP_ERROR_CHECK(esp_efuse_mac_get_default(mac));

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
		esp_wifi_internal_tx(ESP_IF_WIFI_STA, buf, p-buf);
		vTaskDelay(200 / portTICK_PERIOD_MS);
		if (bss == NULL)
			cur_channel = 1 + ((cur_channel+4) % 13);
	}

	free(buf);
}

void
set_essid(char *in)
{
	if (essid != NULL)
		free(essid);
	essid = strndup(in, 32);

	sendbeacon();
}

void
set_brsne(char *in)
{
	int l;
	if (bss != NULL) {
		l = strlen(in);
		l >>= 1;
		bss->rsnelen = hextob(in, NULL, bss->rsne, l);
		if (bss->aid == 0)
			bss->status = Sconn;
		else
			bss->status = Sauth;
	}
}

static uint8_t*
srcaddr(Wifipkt *w)
{
	if((w->fc[1] & 0x02) == 0)
		return w->a2;
	if((w->fc[1] & 0x01) == 0)
		return w->a3;
	return w->a4;
}

static uint8_t*
dstaddr(Wifipkt *w)
{
	if((w->fc[1] & 0x01) != 0)
		return w->a3;
	return w->a1;
}

int
wifihdrlen(Wifipkt *w)
{
	int n;

	n = WIFIHDRSIZE;
	if((w->fc[0] & 0x0c) == 0x08)
		if((w->fc[0] & 0xf0) == 0x80){	/* QOS */
			n += 2;
			if(w->fc[1] & 0x80)
				n += 4;
		}
	if((w->fc[1] & 3) == 0x03)
		n += Eaddrlen;
	return n;
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
	char str[64];
	wifi_config_t cfg;

	gettimeofday(&tv, NULL);
	now = tv.tv_sec * 1000LL + (tv.tv_usec / 1000LL);
	ESP_ERROR_CHECK(esp_efuse_mac_get_default(mac));
	w = (Wifipkt*)p;

	switch (type) {
	case WIFI_PKT_MGMT:
		for (i = 0; i < ap_count && i < DEFAULT_SCAN_LIST_SIZE; i++) {
			if (memcmp(wns[i].bssid, srcaddr(w), 6) == 0) {
				wns[i].lastseen = now;
				break;
			}
		}
		if (i == DEFAULT_SCAN_LIST_SIZE)
			break;
		if (memcmp(srcaddr(w), mac, 6) == 0 ||
			memcmp(dstaddr(w), mac, 6) == 0) {
			sprintf(str, "%02x%02x:", p[0], p[1]);
			mac2str(str + 5, srcaddr(w));
			sprintf(str + 17, ">");
			mac2str(str + 18, dstaddr(w));
			ESP_LOG_LEVEL_LOCAL(ESP_LOG_ERROR, "wifi", "%s", str);
		}
		if (bss != NULL &&
			memcmp(srcaddr(w), bss->bssid, 6) == 0) {
			rssi = packet->rx_ctrl.rssi;
		}
		switch(p[0] & 0xF0) {
		case 0x50: // probe response
		case 0x80: // beacon
			if (i == ap_count)
				ap_count++;
			memcpy(wns[i].bssid, srcaddr(w), 6);
			wns[i].channel = cur_channel;
			p += wifihdrlen(w);
			wns[i].cap = (p[11] << 8) | p[10];
			l = p[13];
			if (l > 32)
				l = 32;
			memcpy(wns[i].ssid, &p[14], l);
			l = 14 + p[13];
			while (((p - packet->payload) + l) < (packet->rx_ctrl.sig_len - 4)) {
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
					/* fall through */
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
			if (essid != NULL) {
				if (bss == NULL) {
					if (strcmp(essid, wns[i].ssid) == 0) {
						bss = &wns[i];
						bss->status = Sconn;
						memset(&cfg, 0, sizeof(cfg));
						snprintf((char*)cfg.sta.ssid, 32, "%s", essid);
						sprintf((char*)cfg.sta.password, "\xFF");
						ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &cfg));
						esp_wifi_connect();
					}
				}
			}
			break;
		case 0xB0:
			if (bss != NULL &&
				memcmp(mac, dstaddr(w), 6) == 0 &&
				memcmp(bss->bssid, srcaddr(w), 6) == 0) {
				if (bss->brsnelen > 0 && bss->rsnelen == 0)
					bss->status = Sneedauth;
				else
					bss->status = Sauth;
			}
			break;
		case 0x10:
		case 0x30:
			if (bss != NULL &&
				memcmp(bss->bssid, srcaddr(w), 6) == 0 &&
				memcmp(mac, dstaddr(w), 6) == 0) {
				p += wifihdrlen(w);
				p += 2;
				l = p[0] | (p[1] << 8);
				p += 2;
				switch(l) {
				case 0x00:
					bss->aid = p[0] | (p[1] << 8);
					if (bss->rsnelen > 0)
						bss->status = Sblocked;
					else
						bss->status = Sassoc;
					break;
				default:
					bss->aid = 0;
					bss->status = Sunassoc;
					break;
				}
			}
			break;
		case 0xc0:
			if (bss != NULL &&
				memcmp(mac, dstaddr(w), 6) == 0 &&
				memcmp(bss->bssid, srcaddr(w), 6) == 0) {
				bss->status = Sunauth;
				bss->aid = 0;

				if (bss->txkey[0]) {
					free(bss->txkey[0]);
					bss->txkey[0] = NULL;
				}
				for (l = 0; l < 5; l++)
					if (bss->rxkey[l]) {
						free(bss->rxkey[l]);
						bss->rxkey[l] = NULL;
					}

				bss = NULL;

				while(etherESP32_eapol_state != 0)
					vTaskDelay(10 / portTICK_PERIOD_MS);

				etherESP32_eapol_len = 0;
				etherESP32_eapol_state = 1;
			}
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
}

static void addpkt(eth_pkt **list, eth_pkt *pkt)
{
	eth_pkt *cur;

	if (*list == NULL)
		*list = pkt;
	else {
		cur = *list;
		while (cur->next != NULL)
			cur = cur->next;
		cur->next = pkt;	
	}
}

static esp_err_t pkt_wifi2eth(void *buffer, uint16_t len, void *eb)
{
	uint8_t *data = (uint8_t*)buffer;
	uint16_t type = (data[12] << 8) | data[13];
	eth_pkt *pkt;
	uint8_t mac[6];
	uint8_t brd[6];
	char src[13];
	char dst[13];

	ESP_ERROR_CHECK(esp_efuse_mac_get_default(mac));
	memset(brd, '\xFF', 6);

	mac2str(src, &data[0]);
	mac2str(dst, &data[6]);
	ESP_LOG_LEVEL_LOCAL(ESP_LOG_ERROR, "wifi", "rx %s>%s %04x", src, dst, type);

	if (memcmp(mac, data, 6) == 0 || memcmp(brd, data, 6) == 0) {
		switch(type) {
		case 0x800:
			if (read800) {
				pkt = calloc(1, sizeof(eth_pkt));
				pkt->msg = malloc(len);
				pkt->len = len;
				memcpy(pkt->msg, data, len);
				while(xSemaphoreTake(mutex800, 20 / portTICK_RATE_MS) != pdTRUE);
				addpkt(&eth800, pkt);
				xSemaphoreGive(mutex800);
			}
			break;
		case 0x806:
			if (read806) {
				pkt = calloc(1, sizeof(eth_pkt));
				pkt->msg = malloc(len);
				pkt->len = len;
				memcpy(pkt->msg, data, len);
				while(xSemaphoreTake(mutex806, 20 / portTICK_RATE_MS) != pdTRUE);
				addpkt(&eth806, pkt);
				xSemaphoreGive(mutex806);
			}
			break;
		case 0x86dd:
			if (read86dd) {
				pkt = calloc(1, sizeof(eth_pkt));
				pkt->msg = malloc(len);
				pkt->len = len;
				memcpy(pkt->msg, data, len);
				while(xSemaphoreTake(mutex86dd, 20 / portTICK_RATE_MS) != pdTRUE);
				addpkt(&eth86dd, pkt);
				xSemaphoreGive(mutex86dd);
			}
			break;
		}
	}
	
	esp_wifi_internal_free_rx_buffer(eb);
	return ESP_OK;
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
	switch (event_id) {
	case WIFI_EVENT_STA_CONNECTED:
		ESP_LOG_LEVEL_LOCAL(ESP_LOG_ERROR, "wifi", "connected");
		esp_wifi_internal_reg_rxcb(WIFI_IF_STA, pkt_wifi2eth);
		break;
	case WIFI_EVENT_STA_DISCONNECTED:
		ESP_LOG_LEVEL_LOCAL(ESP_LOG_ERROR, "wifi", "disconnected");
		esp_wifi_internal_reg_rxcb(WIFI_IF_STA, NULL);
		break;
	default:
		break;
	}
}

void
init_wifi(void)
{
	wifi_second_chan_t chan;

	log_etherESP32 = calloc(1, sizeof(char));
	etherESP32_eapol_state = 0;

	ESP_ERROR_CHECK(nvs_flash_init());

	read800 = read806 = read86dd = 0;
	eth800 = eth806 = eth86dd = NULL;
	vSemaphoreCreateBinary(mutex800);
	vSemaphoreCreateBinary(mutex806);
	vSemaphoreCreateBinary(mutex86dd);

	ESP_ERROR_CHECK(esp_event_loop_create_default());
	ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL));

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

	ESP_ERROR_CHECK(esp_wifi_start());

	ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

	cur_channel = 11;
	ESP_ERROR_CHECK(esp_wifi_set_channel(cur_channel, WIFI_SECOND_CHAN_NONE));
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
getpkt(char *str, eth_pkt **list)
{
	eth_pkt *cur;
	unsigned long l;

	cur = *list;
	*list = (*list)->next;
	memcpy(str, cur->msg, cur->len);
	l = cur->len;
	free(cur->msg);
	free(cur);
	return l;
}

unsigned long
read_data(char *str, int type)
{
	uint8_t mac[6];
	unsigned long l;

	if (bss != NULL) {
		switch (type) {
		case 0x888e:
			while(etherESP32_eapol_state != 1)
				vTaskDelay(10 / portTICK_PERIOD_MS);

			if (etherESP32_eapol_len == 0) { 
				etherESP32_eapol_state = 0;
				return 0;
			}

			ESP_ERROR_CHECK(esp_efuse_mac_get_default(mac));
			memcpy(str, mac, 6);
			memcpy(&str[6], bss->bssid, 6);
			memcpy(&str[12], "\x88\x8e", 2);
			memcpy(&str[14], etherESP32_eapol_data, etherESP32_eapol_len);
			l = etherESP32_eapol_len;
			free(etherESP32_eapol_data);
			etherESP32_eapol_len = 0;
			etherESP32_eapol_state = 2;
			return 14 + l;
		case 0x800:
			while (eth800 == NULL)
				vTaskDelay(10 / portTICK_RATE_MS);

			while(xSemaphoreTake(mutex800, 20 / portTICK_RATE_MS) != pdTRUE);
			l = getpkt(str, &eth800);
			xSemaphoreGive(mutex800);
			return l;
		case 0x806:
			while (eth806 == NULL)
				vTaskDelay(10 / portTICK_RATE_MS);

			while(xSemaphoreTake(mutex806, 20 / portTICK_RATE_MS) != pdTRUE);
			l = getpkt(str, &eth806);
			xSemaphoreGive(mutex806);
			return l;
		case 0x86dd:
			while (eth86dd == NULL)
				vTaskDelay(10 / portTICK_RATE_MS);

			while(xSemaphoreTake(mutex86dd, 20 / portTICK_RATE_MS) != pdTRUE);
			l = getpkt(str, &eth86dd);
			xSemaphoreGive(mutex86dd);
			return l;
		default:
			return 0;
		}
	}

	return 0;
}

unsigned long
write_data(uchar *str, unsigned long length, int type)
{
	char src[13];
	char dst[13];
	Wifipkt *w;
	SNAP *s;
	uchar *buf;
	int l;

	mac2str(src, &str[6]);
	mac2str(dst, &str[0]);
	ESP_LOG_LEVEL_LOCAL(ESP_LOG_ERROR, "wifi", "tx %s>%s %02x%02x", src, dst, str[12], str[13]);

	if (bss != NULL) {
		switch(type) {
		case 0x888e:
			while(etherESP32_eapol_state != 2)
				vTaskDelay(10 / portTICK_PERIOD_MS);

			etherESP32_eapol_data = malloc(length);
			memcpy(etherESP32_eapol_data, str, length);
			etherESP32_eapol_len = length - 14;
			etherESP32_eapol_state = 3;
			return length;
		case 0x800:
		case 0x86dd:
		case 0x806:
			if (length > 0) {
				buf = calloc(1, WIFIHDRSIZE + SNAPHDRSIZE + length);
				w = (Wifipkt*)buf;
				w->fc[0] = 0x08;
				w->fc[1] = 0x01;
				memcpy(w->a1, &str[0], 6);
				memcpy(dstaddr(w), &str[0], 6);
				memcpy(srcaddr(w), &str[6], 6);
				l = wifihdrlen(w);
				s = (SNAP*)(&buf[l]);
				s->dsap = s->ssap = 0xAA;
				s->control = 0x03;
				memset(s->orgcode, 0, 3);
				memcpy(s->type, &str[12], 2);
				l += SNAPHDRSIZE;
				memcpy(&buf[l], &str[14], length - 14);
				l += length - 14;
				ESP_ERROR_CHECK(esp_wifi_internal_tx(ESP_IF_WIFI_STA, buf, l));
				free(buf);
			}
			return length;
		default:
			return 0;
		}
	}

	return 0;
}

unsigned long
read_log(char *out, unsigned long count, unsigned long offset)
{
	return snprintf(out, count, "%s", &log_etherESP32[offset]);
}

void wpa_supplicant_install_ptk_wkey(Wkey*);
void wpa_supplicant_install_gtk_wkey(Wkey*, int);

void
set_key_str(char *in)
{
	Wkey *wkey;
	char *p; 
	char *e;
	int k = 4;
	uchar isptk = 0;

	if (bss == NULL)
		return;

	if (strncmp(in+1, "xkey", 4) == 0) {
		wkey = calloc(1, sizeof(Wkey) + 32);

		if (isdigit(in[5]))
			k = atoi(&in[5]);
		else if (in[5] == ' ')
			isptk = 1;

		if ((p = strstr(in, "ccmp:")) != NULL) {
			wkey->cipher = CCMP;
			wkey->len = 16;
		}
		else if ((p = strstr(in, "tkip:")) != NULL) {
			wkey->cipher = TKIP;
			wkey->len = 32;
		}
		else {
			free(wkey);
			return;
		}

		hextob(p+5, &e, wkey->key, wkey->len);

		if (*e++ != '@') {
			free(wkey);
			return;
		}

		wkey->tsc = strtol(e, NULL, 16);

		if (in[0] == 't') {
			if (bss->txkey[0] != NULL)
				free(bss->txkey[0]);
			bss->txkey[0] = wkey;
		}
		else if (in[0] == 'r') {
			if (bss->rxkey[k] != NULL)
				free(bss->rxkey[k]);
			bss->rxkey[k] = wkey;
		}
		else {
			free(wkey);
			return;
		}

		if (isptk != 0)
			wpa_supplicant_install_ptk_wkey(wkey);
		else
			wpa_supplicant_install_gtk_wkey(wkey, k);
	}

	ESP_LOG_LEVEL_LOCAL(ESP_LOG_ERROR, "wpa", "%s", in);
}
