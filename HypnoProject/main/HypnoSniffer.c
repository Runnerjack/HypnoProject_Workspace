/**
 * Copyright (c) 2018, HypnoProject
 * ESP32 PROBE REQUEST SNIFFER
 *
 * Bonafede Giacomo
 * Ditano Dario
 * Poppa Emanuel
 * Scalabrino Enrico
 *
 *
 * DOCUMENTATION:
 * Espressif GitHub:    https://github.com/espressif/esp-idf/blob/master/examples/protocols/http_request/main/http_request_example_main.c#L54-L73
 * WiFi Driver:         https://docs.espressif.com/projects/esp-idf/en/latest/api-guides/wifi.html
 */


 /****************************
  * INCLUDE, DEFINE, MACRO   *
  ****************************/
/*************************************************  INCLUDE  **********************************************************/

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "driver/gpio.h"
#include "esp_timer.h"

#include "includes/sniffing.h"
#include "includes/wifi_settings.h"
#include "includes/timer.h"

/*************************************************  DEFINE  ***********************************************************/

#define	LED_GPIO_PIN			GPIO_NUM_4
#define	WIFI_CHANNEL_MAX		(13)
#define	WIFI_CHANNEL_SWITCH_INTERVAL	(500)



/*****************************************************
* CONSTANTS, STRUCTS, GLOBAL VARIABLES AND FUNCTIONS *
******************************************************/
/*************************************************  COSTANTS  *********************************************************/

static wifi_country_t wifi_country = {.cc="CN",                                 /* country code string */
                                      .schan=1,                                 /* start channel */
                                      .nchan=13,                                /* total channel number */
                                      .policy=WIFI_COUNTRY_POLICY_AUTO};        /* country policy */
static const char *MEM_ERR="memory_error";
const uint8_t CHANNEL_TO_SNIFF = 1;                                             /* channel to sniff */

/*********************************************   GLOBAL VARIABLES   ***************************************************/

struct buffer_list *head;                                                 /* ptr to first element inside buffer */
struct  buffer_list *curr;                                                /* ptr to current element inside buffer */

/**************************************************  STRUCTS  *********************************************************/
/*  defined inside .h files */

/*************************************************  FUNCTIONS  ********************************************************/

static void wifi_sniffer_init(void);
static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);
void print_proberequest(struct buffer* buf);
uint32_t hash(char str[], int DIM);



/*********************************
 *              MAIN             *
 *********************************/
void
app_main(void)
{
    printf("PROGETTO PDS\n");
    /* WIFI setup */
    wifi_sniffer_init();

    /* selection of the channel to sniff  */
    esp_wifi_set_channel( CHANNEL_TO_SNIFF, WIFI_SECOND_CHAN_NONE);

}



/*************************************
 *      FUNCTIONS IMPLEMENTATION     *
 *************************************/
/************************************************    SNIFFER     ******************************************************/
void
wifi_sniffer_init(void)
{
    printf("wifi_sniffer_init\n");

    /*	Initialize the default NVS partition.	*/
    esp_err_t ret = nvs_flash_init();

    /*  Error handler   */
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES) {			                 /*	ESP_ERR_NVS_NO_FREE_PAGES if the NVS storage contains no empty pages */
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK( ret );

    /*  Initialization buffer list of sniffed packet  */
    head = malloc(sizeof(struct buffer_list));
    if( head == NULL ) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_LOGE(MEM_ERR,"Failed to allocate head of the buffer list\n");
        return;
    }
    head->next = NULL;
    curr = head;

    /* ------------  Wifi/LwIP Initialization phase ------------  */

    tcpip_adapter_init();                                               /*  Creates an LwIP core task and initialize LwIP-related work. */

    ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );        /* Create a system Event task and initialize an application event's callback function.
 *                                                                         Every time there is an event -> event_handler() is called*/
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );                             /* Create the Wi-Fi driver task and initialize the Wi-Fi driver.  */

    /* ------------  WiFi Configuration phase ------------------  */

    ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) );             /* Set country for channel range [1, 13] */
    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );                /* Station mode: in this mode, esp_wifi_start() will init the internal station data,
 *                                                                         while the station’s interface is ready for the RX and TX Wi-Fi data.
 *                                                                         After esp_wifi_connect() is called, the STA will connect to the target AP. */

    /* ------------  WiFi Start phase    -----------------------  */

    ESP_ERROR_CHECK( esp_wifi_start() );                                /* Start the Wi-Fi driver.  */
    printf("TIMESTAMP\t|\tTYPE\t|\tCHANNEL\t|\tSEQ\t|\tRSSI\t|\tMAC ADDRESS\t\t|\tHASH\t\t|\tCRC\t\t|\tSSID\n");
}

esp_err_t
event_handler(void *ctx, system_event_t *event)
{
    /* Each time a packet is received, the registered callback function will be called. */

    esp_wifi_set_promiscuous(true);                                     /* Set promiscuous mode */
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);       /* Register the RX callback function -> wifi_sniffer_packet_handler()  */
    return ESP_OK;
}

void
wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type)
{
    /*  Parameters:
     *  buff: Data received. Type of data in buffer (wifi_promiscuous_pkt_t or wifi_pkt_rx_ctrl_t) indicated by ‘type’ parameter.
     *  type: Promiscuous packet type.
     *  */

    if (type != WIFI_PKT_MGMT)                                                    /* Check on type of sniffed packet  */
        return;

    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    if( hdr->frame_ctrl[0] != PROBE_REQUEST_SUBTYPE)                              /* Keep only PROBE REQUEST */
        return;

    int packet_length = ppkt->rx_ctrl.sig_len;

    struct buffer b;                                                              /* Temp element Buffer  */

    /*  Put the sniffed info into the buffer element    */

    //b.timestamp da impostare dopo aver implementato il timer
    //b.timestamp = ((double) timer_val / TIMER_SCALE)*1000000;//ppkt->rx_ctrl.timestamp;

    b.channel = ppkt->rx_ctrl.channel;
    b.seq_ctl/*[0]*/ = hdr->seq_ctl;
    b.rssi = ppkt->rx_ctrl.rssi;
    for (int j=0; j<6; j++)
        b.addr[j] = hdr->addr2[j];
    b.ssid_length = ipkt->payload[1];
    for (int i=0; i<b.ssid_length; i++)
        b.ssid[i] = (char)ipkt->payload[i+2];
    for (int i=0, j=packet_length-4; i<4; i++, j++)
        b.crc[i] = ipkt->payload[j];

    /*** Packet hash ***/
    // Sequence + Address + SSID
    int DIM = 16 + b.ssid_length; //54;

    /*  Generation of the HASHcode  */
    char hashCode[DIM];
    sprintf(hashCode, "%04x%02x%02x%02x%02x%02x%02x",
            b.seq_ctl,
            b.addr[0], b.addr[1],b.addr[2], b.addr[3],b.addr[4],b.addr[5]);
    for (int i=0; i<b.ssid_length; i++)
        hashCode[16+i] = (char) b.ssid[i];

    hashCode[16+b.ssid_length] = '\0';

    b.hash = hash(hashCode, DIM);

    /* Add buffer to buffer_list */
    curr->data = b;

    print_proberequest(&(curr->data));
    struct buffer_list *temp = malloc(sizeof(struct buffer_list));
    if( temp != NULL ) {
        temp->next = NULL;
        curr->next = temp;
        curr = temp;

    } else {
        ESP_LOGE(MEM_ERR,"Couldn't allocate new element of the buffer list.\n");
    }
}

void
print_proberequest(struct buffer* buf){
    printf("%08d\t|\tPROBE\t|\t%02d\t|\t%04x\t|\t%02d\t|\t"
           "%02x:%02x:%02x:%02x:%02x:%02x\t|\t%u\t|\t" ,
           buf->timestamp,
           buf->channel,
           buf->seq_ctl/*[0], buf->seq_ctl[1]*/,
           buf->rssi,
           buf->addr[0],buf->addr[1],buf->addr[2],
           buf->addr[3],buf->addr[4],buf->addr[5],
           buf->hash
    );
    for (int i=0; i<4; i++)
        printf("%02x", buf->crc[i]);
    printf("\t|\t");
    for (int i=0; i<buf->ssid_length; i++)
        printf("%c", (char)buf->ssid[i]);
    printf("\n");
}

uint32_t
hash(char str[], int DIM)
{
    /* Creates hash djb2 algorithm */
    uint32_t hash = 5381;

    for(int i = 0; i < DIM; i++){
        hash = ((hash << 5) + hash) + str[i]; /* hash * 33 + str[i] */
    }
    return hash;
}

/**************************************************    TIMER    *******************************************************/

/**************************************************    SYNC     *******************************************************/

/**************************************************    CLIENT   *******************************************************/