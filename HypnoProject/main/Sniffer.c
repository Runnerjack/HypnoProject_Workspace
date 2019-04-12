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


/*==== Added Headers Files ====*/
//#include "esp_types.h"
//#include "freertos/queue.h"
//#include "soc/timer_group_struct.h"
//#include "driver/periph_ctrl.h"
//#include "driver/timer.h"

#include "includes/sniffing.h"
#include "includes/timer.h"
#include "includes/wifi_settings.h"
//#include "includes/timer.h"

/*************************************************  DEFINE  ***********************************************************/

#define	LED_GPIO_PIN			GPIO_NUM_4
#define	WIFI_CHANNEL_MAX		(13)
#define	WIFI_CHANNEL_SWITCH_INTERVAL	(500)


/*==== Defined Macro Value ====*/

//#define TIMER_DIVIDER         16                                                //  Hardware timer clock divider
//#define TIMER_SCALE           (TIMER_BASE_CLK / TIMER_DIVIDER)                  // convert counter value to seconds
//#define TIMER_INTERVAL0_SEC   (60)                                              // sample test interval for the first timer
//#define TIMER_INTERVAL1_SEC   (60)                                              // sample test interval for the second timer
//#define TEST_WITHOUT_RELOAD   0                                                 // testing will be done without auto reload
//#define TEST_WITH_RELOAD      1                                                 // testing will be done with auto reload


/*****************************************************
* CONSTANTS, STRUCTS, GLOBAL VARIABLES AND FUNCTIONS *
******************************************************/
/*************************************************  COSTANTS  *********************************************************/

static wifi_country_t wifi_country = {.cc="CN",                                     /* country code string */
                                      .schan=1,                                     /* start channel */
                                      .nchan=13,                                    /* total channel number */
                                      .policy=WIFI_COUNTRY_POLICY_AUTO};            /* country policy */
static const char *MEM_ERR="memory_error";
const uint8_t CHANNEL_TO_SNIFF = 1;                                                 /* channel to sniff */

/*********************************************   GLOBAL VARIABLES   ***************************************************/

struct buffer_list *head;                                                           /* ptr to first element inside buffer */
struct  buffer_list *curr;                                                          /* ptr to current element inside buffer */

//xQueueHandle timer_queue;
//TaskHandle_t HandleTask = NULL;                                                   /* In case we want delete task */
uint32_t sniff_count, count = 0;                                             
bool stop1 = false, stop2 = false;
int turn = 1;                                                                       /* 1->timer_evt_task | 2->wifi_sniffer_packet_handler */

/**************************************************  STRUCTS  *********************************************************/
/*  defined inside .h files */


//typedef struct {
//    int type;  // the type of timer's event
//    int timer_group;
//    int timer_idx;
//   uint64_t timer_counter_value;
//} timer_event_t;


/*************************************************  FUNCTIONS  ********************************************************/

static void wifi_sniffer_init(void);
static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);
void print_proberequest(struct buffer* buf);
uint32_t hash(char str[], int DIM);


static void print_timer_counter(uint64_t counter_value);
static void print_timestamp_buffer(uint64_t counter_value);
void IRAM_ATTR timer_group0_isr(void *para);
static void tg0_timer_init(int timer_idx, bool auto_reload, double timer_interval_sec);
static void timer_evt_task(void *arg);


/*********************************
 *              MAIN             *
 *********************************/
void
app_main(void)
{
    //Create queue of timer events
    timer_queue = xQueueCreate(10, sizeof(timer_event_t));

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
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES) {			                                /*	ESP_ERR_NVS_NO_FREE_PAGES if the NVS storage contains no empty pages */
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

    tcpip_adapter_init();                                                           /* Creates an LwIP core task and initialize LwIP-related work. */

    ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );                    /* Create a system Event task and initialize an application event's callback function.
 *                                                                                  Every time there is an event -> event_handler() is called*/
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );                                         /* Create the Wi-Fi driver task and initialize the Wi-Fi driver.  */

    /* ------------  WiFi Configuration phase ------------------  */

    ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) );                         /* Set country for channel range [1, 13] */
    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );                            /* Station mode: in this mode, esp_wifi_start() will init the internal station data,
 *                                                                                  while the station’s interface is ready for the RX and TX Wi-Fi data.
 *                                                                                  After esp_wifi_connect() is called, the STA will connect to the target AP. */

    /* -----------------  WiFi Start phase  --------------------- */

    ESP_ERROR_CHECK( esp_wifi_start() );                                            /* Start the Wi-Fi driver.  */

    /* ------------------  Timer Start Phase  ------------------- */

    tg0_timer_init(TIMER_1, TEST_WITH_RELOAD, TIMER_INTERVAL1_SEC);                          
    
    /* ---------------  Task Initialization Phase  -------------- */

    /*  Creation task at timer's interrupt  */

    xTaskCreate(timer_evt_task, "timer_evt_task", 2048, NULL, 5, &HandleTask);

    /* ----------------------  Info Grid  ----------------------- */

    printf("TIMESTAMP\t|\tTYPE\t|\tCHANNEL\t|\tSEQ\t|\tRSSI\t|\tMAC ADDRESS\t\t|\tHASH\t\t|\tCRC\t\t|\tSSID\n\n");
    //printf("TIMESTAMP\t|\tTYPE\t|\tCHANNEL\t\t|\tSEQ\t|\tRSSI\t|\tMAC ADDRESS\t|\tHASH\t|\tCRC\t|\tSSID\n");
    
}

esp_err_t
event_handler(void *ctx, system_event_t *event)
{

    /* Each time a packet is received, the registered callback function will be called. */

    esp_wifi_set_promiscuous(true);                                                 /* Set promiscuous mode */
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);                   /* Register the RX callback function -> wifi_sniffer_packet_handler()  */


    return ESP_OK;
}

void
wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type)
{
    /*  Parameters:
     *  buff: Data received. Type of data in buffer (wifi_promiscuous_pkt_t or wifi_pkt_rx_ctrl_t) indicated by ‘type’ parameter.
     *  type: Promiscuous packet type.
     *  */

    if (type != WIFI_PKT_MGMT)                                                      /* Check on type of sniffed packet  */
        return;

    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    if( hdr->frame_ctrl[0] != PROBE_REQUEST_SUBTYPE)                                /* Keep only PROBE REQUEST */
        return;

    int packet_length = ppkt->rx_ctrl.sig_len;

    struct buffer b;                                                                /* Temp element Buffer  */

    /*  Put the sniffed info into the buffer element    */
    
    uint64_t timer_value;
    timer_get_counter_value(0, TIMER_1, &timer_value);                              //****POCO ELEGANTE, DA RIVEDERE
    b.timestamp = timer_value;
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
    /* Sequence + Address + SSID */
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

        /* ==== Critical section ==== */
        stop2 = true;
        turn = 1;
        while(stop1 && turn == 1);
        count++;
        stop2 = false;

    } else {
        ESP_LOGE(MEM_ERR,"Couldn't allocate new element of the buffer list.\n");
    }
}


void
print_proberequest(struct buffer* buf){                                             
    print_timestamp_buffer(buf->timestamp);                                         /* Single function to print timestamp in floating point with the correct value */           
    printf("|\tPROBE\t|\t%02d\t|\t%04x\t|\t%02d\t|\t"
           "%02x:%02x:%02x:%02x:%02x:%02x\t|\t%8u\t|\t" ,
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


/* Function which prints true time value */

/* A simple helper function to print the raw timer counter value and the counter value converted to seconds. */

static void print_timer_counter(uint64_t counter_value)
{
    printf("Counter: 0x%08x%08x\n", (uint32_t) (counter_value >> 32), (uint32_t) (counter_value));
    printf("Time   : %.8f s\n\n", (double) counter_value / TIMER_SCALE);
}


/* Simple function to print the counter value (timestamp of catched packets) converted to seconds */

static void print_timestamp_buffer(uint64_t counter_value)
{
    printf("%06.3f s\t", (double) counter_value / TIMER_SCALE);
}


/* Timer group0 ISR handler */
/* Note:
 * We don't call the timer API here because they are not declared with IRAM_ATTR.
 * If we're okay with the timer irq not being serviced while SPI flash cache is disabled,
 * we can allocate this interrupt without the ESP_INTR_FLAG_IRAM flag and use the normal API. */

void IRAM_ATTR timer_group0_isr(void *para)
{
    int timer_idx = (int) para;

    // Retrieve the interrupt status and the counter value from the timer that reported the interrupt
    uint32_t intr_status = TIMERG0.int_st_timers.val;
    TIMERG0.hw_timer[timer_idx].update = 1;
    uint64_t timer_counter_value = ((uint64_t) TIMERG0.hw_timer[timer_idx].cnt_high) << 32 | TIMERG0.hw_timer[timer_idx].cnt_low;

    // Prepare basic event data that will be then sent back to the main program task 
    timer_event_t evt;
    evt.timer_group = 0;
    evt.timer_idx = timer_idx;
    evt.timer_counter_value = timer_counter_value;

    // Clear the interrupt and update the alarm time for the timer with without reload
    if ((intr_status & BIT(timer_idx)) && timer_idx == TIMER_0) {
        evt.type = TEST_WITHOUT_RELOAD;
        TIMERG0.int_clr_timers.t0 = 1;
        timer_counter_value += (uint64_t) (TIMER_INTERVAL0_SEC * TIMER_SCALE);
        TIMERG0.hw_timer[timer_idx].alarm_high = (uint32_t) (timer_counter_value >> 32);
        TIMERG0.hw_timer[timer_idx].alarm_low = (uint32_t) timer_counter_value;
    } else if ((intr_status & BIT(timer_idx)) && timer_idx == TIMER_1) {
        evt.type = TEST_WITH_RELOAD;
        TIMERG0.int_clr_timers.t1 = 1;
    } else {
        evt.type = -1; // not supported even type
    }

    // After the alarm has been triggered we need enable it again, so it is triggered the next time
    TIMERG0.hw_timer[timer_idx].config.alarm_en = TIMER_ALARM_EN;

    // Now just send the event data back to the main program task
    xQueueSendFromISR(timer_queue, &evt, NULL);
}



/* Initialize selected timer of the timer group 0 */
/* timer_idx - the timer number to initialize
 * auto_reload - should the timer auto reload on alarm?
 * timer_interval_sec - the interval of alarm to set */

static void tg0_timer_init(int timer_idx, bool auto_reload, double timer_interval_sec)
{   
    // Select and initialize basic parameters of the timer

    printf("\n\nINITIALIZING TIMER_%d\n\n", timer_idx);

    timer_config_t config;
    config.divider = TIMER_DIVIDER;
    config.counter_dir = TIMER_COUNT_UP;
    config.counter_en = TIMER_PAUSE;
    config.alarm_en = TIMER_ALARM_EN;
    config.intr_type = TIMER_INTR_LEVEL;
    config.auto_reload = auto_reload;
    timer_init(TIMER_GROUP_0, timer_idx, &config);

    // Timer's counter will initially start from value below. Also, if auto_reload is set, this value will be automatically reload on alarm
    timer_set_counter_value(TIMER_GROUP_0, timer_idx, 0x00000000ULL);

    // Configure the alarm value and the interrupt on alarm
    timer_set_alarm_value(TIMER_GROUP_0, timer_idx, timer_interval_sec * TIMER_SCALE);
    timer_enable_intr(TIMER_GROUP_0, timer_idx);
    timer_isr_register(TIMER_GROUP_0, timer_idx, timer_group0_isr, (void *) timer_idx, ESP_INTR_FLAG_IRAM, NULL);

    printf("\nTIMER_%d SET TO %.2f second(s) -> STARTING...\n\n\n\n", timer_idx, timer_interval_sec);
    timer_start(TIMER_GROUP_0, timer_idx);
}



/* The main task of this example program. */

static void timer_evt_task(void *arg)
{
    while (1) {

        timer_event_t evt;
        xQueueReceive(timer_queue, &evt, portMAX_DELAY);

        //if(evt.timer_idx == TIMER_0)
        //{
        //   vTaskDelete(HandleTask);
        //    return;
        //}

        /* ==== Critical section ==== */
        stop1 = true;
        turn = 2;
        while(stop2 && turn == 2);
        sniff_count = count;
        count = 0;
        stop1 = false;

        // Print information that the timer reported an event
        //if (evt.type == TEST_WITHOUT_RELOAD) {
        //    printf("\n    Example timer without reload\n");                                     //Not autoreloaded
        //} else if (evt.type == TEST_WITH_RELOAD) {
        //    printf("\n    Example timer with auto reload\n");                                   //Autoreloaded
        //} else {
        //    printf("\n    UNKNOWN EVENT TYPE\n");
        //}
        //printf("Group[%d], timer[%d] alarm event\n", evt.timer_group, evt.timer_idx);

        // Print the timer values passed by event
        printf("\n\nPer adesso stampiamo cose a muzzo, qui andrà poi l'interrupt per il tcp->client-server\n");
        //printf("------- EVENT TIME --------\n");
        //print_timer_counter(evt.timer_counter_value);

        // Print the timer values as visible by this task 
        printf("-------- TASK TIME --------\n");

        uint64_t task_counter_value;
        timer_get_counter_value(evt.timer_group, evt.timer_idx, &task_counter_value);
        print_timer_counter(task_counter_value);

        /* ----------------------  Info Grid  ----------------------- */

        printf("TIMESTAMP\t|\tTYPE\t|\tCHANNEL\t|\tSEQ\t|\tRSSI\t|\tMAC ADDRESS\t\t|\tHASH\t\t|\tCRC\t\t|\tSSID\n\n");
    }
}


/**************************************************    SYNC     *******************************************************/

/**************************************************    CLIENT   *******************************************************/