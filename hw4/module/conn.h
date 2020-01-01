
#define FTP_PROXY_PORT 210
#define HTTP_PROXY_PORT 800
#define DEFAULT_SIZE 10
#define MAX_ROW_SIZE 70

typedef enum {
	SYN_SENT = 1,
	SYN_ACK_SENT = 2,
	ESTABLISHED = 3,
	FIN_WAIT_1 = 4,
	FIN_WAIT_2 = 5,
	LAST_ACK_1 = 6,
	LAST_ACK_2 = 7,
	FTP_OPEN = 8,
} state_t;

typedef struct {
	unsigned int src_ip;
	int src_port;
	unsigned int dst_ip;
	int dst_port;
	state_t state;
} conn_t;

static conn_t** conn_list;
static int conn_size = 0;
static int conn_arr_size = DEFAULT_SIZE;
static int allocnt = 0;

unsigned int tcp_enforce(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port);

int is_matching(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port);

conn_t* add_new_connection(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port);

int remove_connection(conn_t* conn);

ssize_t conn_display(struct device *dev, struct device_attribute *attr, char *buf);

void conn_setup(void);

void conn_clear(void);
