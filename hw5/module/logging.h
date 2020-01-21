#include "fw.h"
#ifndef LOGGING_H
#define LOGGING_H

#define DEFAULT_LOG_SIZE 10
#define MAX_LINE 70
#define MAX_ROW_LENGTH 70

// because there is not hooknum field in log_row_t. please consider adding it the the struct.
typedef struct{
	int hooknum;
	log_row_t* l;
} log_piece;


static log_piece* log_list;
static int arr_size = DEFAULT_LOG_SIZE;
static int log_num = 0;

void inc(void);
void dec(void);

ssize_t log_reset(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
char* log_str(void);

log_piece* create_log(unsigned int src_ip, unsigned int dst_ip, int src_port, int dst_port, unsigned char protocol, int hooknum,int action, int reason);

int log_open(struct inode *_inode, struct file *_file);
ssize_t log_read(struct file *f, char *buff, size_t length, loff_t *offp);

ssize_t log_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

void register_log_device(void);

void register_reset_device(void);

void add_log(log_piece* l);

int search_log(log_piece* l);

#endif /* LOGGING_H */
