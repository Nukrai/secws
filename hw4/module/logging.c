#include "fw.h"
#include "logging.h"
#include <linux/time.h>
//known code exmaple for MIN
#define MIN(a,b) (((a)<(b))?(a):(b)) 
#define fd 0
static int allocnt = 0;
//memory tracking
void inc(void){
        allocnt++;
}
void dec(void){
        allocnt--;
}
// log device open - return 0
int log_open(struct inode *_inode, struct file *_file){
	return fd;	
}
// log device write function - every write is reset
ssize_t log_reset(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){	
	//clean log
	for(int i = 0; i < log_num; i++){
		kfree(log_list[i].l);
		dec();	
	}
	kfree(log_list);
	dec();
	// allocate new list
	log_list = kcalloc(DEFAULT_LOG_SIZE, sizeof(log_piece), GFP_ATOMIC);
	inc();
	log_num = 0;
	arr_size = DEFAULT_LOG_SIZE;
	// track mem. allocations
	printk("\n[firewall][alloc count = %d]\n", allocnt);
	return count;
}

// create log for packet
log_piece* create_log(unsigned int src_ip, unsigned int dst_ip, int src_port, int dst_port, unsigned char protocol, int hooknum, int action, int reason){
	log_piece* p = kcalloc(1, sizeof(log_piece), GFP_ATOMIC);
	inc();	
	p -> hooknum = hooknum;
	log_row_t* l = kcalloc(1, sizeof(log_row_t), GFP_ATOMIC);
	inc();
	// timestamp
	struct timeval spec;
	do_gettimeofday(&spec);
	time_t now = spec.tv_sec;
	l -> timestamp = now;
	l -> protocol = protocol;
	l -> action = action;
	l -> src_ip = src_ip;
	l -> dst_ip = dst_ip;
	l -> src_port = src_port;
	l -> dst_port = dst_port;
	l -> reason = reason;
	l -> count = 1;
	p -> l = l;
	return p;
}



char* log_str(){
	if(log_num == 0){
		return NULL;
	}
	char* ret = kcalloc(MAX_ROW_LENGTH * log_num, sizeof(char), GFP_ATOMIC);
	char* str= kcalloc(MAX_ROW_LENGTH, sizeof(char), GFP_ATOMIC);
	inc();
	inc();
	char* free_str = str; // for kfree()
	for(int i = 0; i < log_num; i++){
		log_piece p = log_list[i];
		if(!(p.l)){
			printk("[p.l is null], %d q", log_num);
			return NULL;
		}
		log_row_t log = *(p.l); 
		//format low row
		int i = sprintf(str, "%lu %u %u %u %u %hhu %d %d %d %d",
			log.timestamp,
			log.src_ip,
			log.dst_ip,
			log.src_port,
			log.dst_port,
			log.protocol,
			p.hooknum,
			log.action,
			log.reason,
			log.count);
		ret = strcat(ret,str);
		if(i != log_num - 1){
			ret = strcat(ret, "\n");
		}
	}
	kfree(free_str);
	dec();
	return ret;
}

// loh read function
ssize_t log_read(struct file *f, char *buff, size_t length, loff_t *offp){
	char* log = log_str();
	if(log == NULL || offp == NULL || (*offp) != 0){
		// no reading in practice
		return 0;
	}
	length = MIN(length, strlen(log));
	// copy log to user buffer
	if(copy_to_user(buff, log, length)){
		printk("[firewall][copy to user problem]");
		return -EFAULT;
	}
	*offp += length; // to notify that we read
	kfree(log);
	dec();
	return length;
	
}

// ad log piece to the log
void add_log(log_piece* p){
	log_piece* old_list;
	if(p == NULL){
		return;
	}
	if(search_log(p) == 0){ // log is already present
		kfree(p -> l);
		kfree(p);
		dec();
		dec();
		return;
	}
	if(log_num == arr_size){ // need to expand the array
		old_list = log_list;
		log_list = kcalloc(log_num*2,sizeof(log_piece), GFP_ATOMIC);
		inc();
		for(int i = 0; i<log_num;i++){
			log_list[i] = old_list[i];
		}
		arr_size *= 2;
		kfree(old_list);
		dec();
	}
	log_list[log_num].hooknum = p -> hooknum;
	log_list[log_num].l = p -> l;
	kfree(p);
	dec();
	log_num++;			
	return;
}

// search the log for previous log piece
int search_log(log_piece* p){
	if(p == NULL){
		return -1;
	}
	log_row_t* l = p->l;
	if(l == NULL){
		printk("[p -> l] is [null]");
		return -1;
	}
	int is_eq;
	for(int i = 0; i < log_num; i++){
		log_piece piece = log_list[i];
		if((piece.l) == NULL){	
			printk("[piece.l] is [null]");
			continue;
		}
		log_row_t log = *(piece.l);
		is_eq = 0;
		if(log.src_ip != l -> src_ip || log.dst_ip != l -> dst_ip){
			is_eq = 1;
		}
		if(log.src_port != l -> src_port || log.dst_port != l -> dst_port){
                        is_eq = 1;
                }
		if(log.reason != l->reason || log.action != l->action){
                        is_eq = 1;
                }
		if(piece.hooknum != p->hooknum){
			is_eq = 1;
		}
		if(is_eq == 0){
			(piece.l -> count)++;
			piece.l -> timestamp = l->timestamp;
			return 0;
		}
	}
	return 1;
}


