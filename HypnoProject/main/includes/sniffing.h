/***  Constants ***/

#define	LED_GPIO_PIN					          GPIO_NUM_4
#define	WIFI_CHANNEL_MAX				        (13)
#define	WIFI_CHANNEL_SWITCH_INTERVAL	  (500)
#define PROBE_REQUEST_SUBTYPE			      0x40
#define PACKET_SIZE                     56

/***  Structs ***/

/* 	Struct used to store the sniffed requests	*/
struct buffer {
	unsigned timestamp:32;
	unsigned channel:8;
	unsigned seq_ctl:16;
	signed rssi:8;
	uint8_t addr[6];
	uint8_t ssid_length;
	uint8_t ssid[32];
	uint8_t crc[4];
	uint32_t hash;
};

/*	List of all the sniffed requests:	LIST of BUFFER	*/
struct buffer_list {
	struct buffer data;
	struct buffer_list *next;
};

/* Store the elements of a mac header	*/
typedef struct {
	uint8_t frame_ctrl[2];								/*	unsigned frame_ctrl:16	*/
	uint8_t duration[2];								/*	unsigned duration_id:16	 */

	uint8_t addr1[6]; 									/* receiver address */
	uint8_t addr2[6]; 									/* sender address */
	uint8_t addr3[6]; 									/* filtering address */
	unsigned seq_ctl:16;

} wifi_ieee80211_mac_hdr_t;

/* Store the elements of a layer 2 packet	*/
typedef struct {
	wifi_ieee80211_mac_hdr_t hdr;
	uint8_t payload[0]; 								/* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

/* Used in case of management frames	*/
typedef struct {
	wifi_vendor_ie_type_t type;
	uint8_t length;
	vendor_ie_data_t data;
} wifi_ieee80211_ie_t;
