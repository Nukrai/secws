
#define FTP_PROXY_PORT 210
#define HTTP_PROXY_PORT 800
#define DEFAULT_SIZE 10
#define MAX_ROW_SIZE 70

typedef enum {
	CLOSED = 0,
	SYN_SENT = 1,
	SYN_RCVD = 2,
	ESTABLISHED = 4,
	FIN_WAIT_1 = 5,
	FIN_WAIT_2 = 6,
	CLOSING = 7,
	CLOSE_WAIT = 8,
	LAST_ACK = 9,
//	FTP_OPEN = 10,
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

unsigned int tcp_enforce(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port, int syn, int ack, int fin, int rst);

int is_matching(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port, int fin, int rst, conn_t* conn);

int add_new_connection(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port, state_t state);

int remove_connection(conn_t* conn);

ssize_t conn_display(struct device *dev, struct device_attribute *attr, char *buf);

char* conn_str(void);

void conn_setup(void);

void conn_clear(void);
