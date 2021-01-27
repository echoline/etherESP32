#include "wifi.h"

static esp_netif_t *sta_netif = NULL;                                           

void
init_wifi(void)
{
	ESP_ERROR_CHECK(nvs_flash_init());

	ESP_ERROR_CHECK(esp_netif_init());
	sta_netif = esp_netif_create_default_wifi_sta();
	assert(sta_netif != NULL);

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
}

void
get_mac_address(char *str)
{
	uint8_t mac[6];

	ESP_ERROR_CHECK(esp_efuse_mac_get_default(mac));

	sprintf(str, "%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

unsigned long
read_stats(char *str)
{
	char mac[13];
	unsigned long ret;

	get_mac_address(mac);

	ret = sprintf(str, "in: %d\n"
			"link: %d\n"
			"out: %d\n"
			"crc errs: %d\n"
			"overflows: %d\n"
			"soft overflows: %d\n"
			"framing errs: %d\n"
			"buffer errs: %d\n"
			"output errs: %d\n"
			"prom: %d\n"
			"mbps: %d\n"
			"addr: %s\n",
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, mac);

	return ret;
}
