#ifndef CONN_H
#define CONN_H

#define FTP_PROXY_PORT (210)
#define FTP_PORT (21)

#define HTTP_PROXY_PORT (800)
#define HTTP_PORT (80)

#define STMP_PROXY_PORT (250)
#define STMP_PORT (25)

#define DEFAULT_SIZE (10)
#define MAX_ROW_SIZE (70)

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
	int proxy_port;
	state_t state;
} conn_t;

static conn_t** conn_list;
static int conn_size = 0;
static int conn_arr_size = DEFAULT_SIZE;
static int allocnt = 0;

static conn_t ftp_connection;

conn_t* get_ftp20(void);

void last_ack_cleanup(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port);

int get_proxy_port(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port);

void update_proxy_port(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port, int proxy_port);

unsigned int tcp_enforce(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port, int syn, int ack, int fin, int rst);

int is_matching(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port, int syn, int fin, int rst, conn_t* conn);

int add_new_connection(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port, state_t state);

int remove_connection(conn_t* conn);

ssize_t conn_display(struct device *dev, struct device_attribute *attr, char *buf);

ssize_t ftp_display(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t ftp_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);


char* conn_str(void);

void conn_setup(void);

void conn_clear(void);

#endif /* CONN_H */
