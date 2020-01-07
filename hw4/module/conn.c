#include "fw.h"
#include "conn.h"

void conn_inc(void){
	allocnt++;
}
void conn_dec(void){
	allocnt--;
}

conn_t* get_ftp20(void){
	return &ftp_connection;
}

ssize_t ftp_display(struct device *dev, struct device_attribute *attr, char *buf){
	buf[0] = '\0';
	sprintf(buf, "%u %d %u %d",
		ftp_connection.src_ip,
		ftp_connection.src_port,
		ftp_connection.dst_ip,
		ftp_connection.dst_port
	
	);
	return strlen(buf);
}

ssize_t ftp_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){
	char*  str = kmalloc(count, GFP_ATOMIC);
        char* free_str = str;
        conn_inc();
        char* l;
        int i = 0;
        rule_num = 0;
	unsigned int src_ip;
	unsigned int dst_ip;
	int src_port;
	int dst_port;

	strncpy(str, buf, count);
	i = sscanf(str, "%u %d %u %d", &src_ip, &src_port, &dst_ip, &dst_port);
	if(i < 4 && i >= 0){
		return count;
	}
	ftp_connection.src_ip = src_ip;
	ftp_connection.dst_ip = dst_ip;
	ftp_connection.src_port = src_ip;
	ftp_connection.dst_port = dst_port;
	return count;
}


int is_matching(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port, int syn, int fin, int rst, conn_t* conn){
	if(src_ip == conn -> src_ip && src_port == conn -> src_port &&
	   dst_ip == conn -> dst_ip && dst_port == conn -> dst_port &&
	   (rst || fin || (conn -> state == CLOSED && syn) )){
		return 2;
	}
	//listen  to rst's in opposite direction 
	if(dst_ip == conn -> src_ip && dst_port == conn -> src_port &&
           src_ip == conn -> dst_ip && src_port == conn -> dst_port){
                return 1;
        }
	//TODO: add FTP port = 20 logic
	return 0;
}

int get_proxy_port(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port){
	conn_t* conn = NULL;
	for(int i = 0; i < conn_size; ++i){
		conn = conn_list[i];
		if(is_matching(src_ip, src_port, dst_ip, dst_port, 0, 0, 0, conn) == 1){
			return conn -> proxy_port;
		}
	}
	return -1;
}

void update_proxy_port(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port, int proxy_port){
	conn_t* conn = NULL;
        for(int i = 0; i < conn_size; ++i){
                conn = conn_list[i];
                if(is_matching(src_ip, src_port, dst_ip, dst_port, 0, 0, 0, conn) == 1){
                        conn -> proxy_port = proxy_port;
			return;
                }
        }
        return;
}

unsigned int tcp_enforce(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port, int syn, int ack, int fin, int rst){
	conn_t* conn;
	int match;
	unsigned int ret = NF_DROP;
	for(int i = 0 ; i < conn_size; ++i){
		printk("[firewall] checking conn number %d, src port %d, syn=%d, ack=%d, fin=%d, rst=%d\n",i, src_port,syn,ack,fin,rst);
		conn = conn_list[i];
		if((match = is_matching(src_ip, src_port, dst_ip, dst_port, syn, fin, rst, conn)) != 0){
			if(rst){
				remove_connection(conn);
				i--;
				ret =  NF_ACCEPT;
				continue;
			}
			switch(conn -> state){
				case CLOSED:
					printk("[firewall] conn state: CLOSED\n");
					if(syn && !ack && !fin){
						conn -> state = (match == 1 ? SYN_RCVD : SYN_SENT);
						ret = NF_ACCEPT;
					}
					continue;

				case SYN_SENT:
					printk("[firewall] conn state: SYN_SENT\n");
					if(syn && ack && !fin){
						conn -> state = ESTABLISHED;
						printk("[firewall] conn *changed* to EST\n");
						ret = NF_ACCEPT;
					}
					continue;

				case SYN_RCVD:
					printk("[firewall] conn state: SYN_RCVD\n");
					if(ack && !syn && !fin){
						conn -> state = ESTABLISHED;
						printk("[firewall] conn *changed* to EST\n");
						ret = NF_ACCEPT;
						continue;
					}
					if(fin && match == 2){
						conn -> state = FIN_WAIT_1;
					}
					continue;

				case ESTABLISHED:
					printk("[firewall] conn state: EST\n");
					if(syn)
						continue;
					if(fin){
						conn -> state = (match == 1 ? CLOSE_WAIT : FIN_WAIT_1);			
						printk("[firewall] conn *changed* to %s\n", ((match == 1) ? "CLOSE_WAIT" : "FIN_WAIT_1"));
						ret = NF_ACCEPT;
						continue;
					}
					ret = NF_ACCEPT;
					continue;

				case FIN_WAIT_1:
					printk("[firewall] conn state: f1\n");
					if(syn)
						continue;

					if(ack && fin && match == 1){
						remove_connection(conn);
						i--;
						printk("[firewall] conn CLOSED!\n");
						ret = NF_ACCEPT;
						continue;
					}
					if(fin && match == 2){
						ret = NF_ACCEPT; 
						continue;
					}
					if(ack && match == 1){
						conn -> state = FIN_WAIT_2;
						printk("[firewall] conn *changed* to FIN_WAIT_2\n");
						ret = NF_ACCEPT;
						continue;
					}
					if(fin && match == 1){
						conn -> state = CLOSING;
						printk("[firewall] conn *changed* to CLOSING\n");
					}
					ret = NF_ACCEPT;
					continue;

				case FIN_WAIT_2:
					printk("[firewall] conn state: f2\n");
					if(syn || (!ack && match == 2))
						continue;
					if(fin && match == 1){
						remove_connection(conn);
						i--;
						printk("[firewall] conn CLOSED!\n");
						ret = NF_ACCEPT;
					}
					ret = NF_ACCEPT;
					continue;

				case CLOSING:
					printk("[firewall] conn state: closing\n");
					if(syn)
						continue;
					if(ack && !fin){
						if(match == 1){
							i--;
							remove_connection(conn);
							printk("[firewall] conn CLOSED!\n");
						}
						ret = NF_ACCEPT;
					}
					continue;

				case CLOSE_WAIT:
					printk("[firewall] conn state: close wait\n");
					if(syn)
						continue;
					if(match == 1){
						if(ack)
							ret = NF_ACCEPT;
						continue;
					}
					if(ack){
						if(fin){
							conn -> state = LAST_ACK;
							printk("[firewall] conn *changed* to LASK_ACK\n");
						}
						ret = NF_ACCEPT;
						continue;
					}
					if(fin){
						conn -> state = LAST_ACK;
						printk("[firewall] conn *changed* to LAST_ACK\n");
						ret = NF_ACCEPT;
					}
					continue;
				case LAST_ACK:
					printk("[firewall] conn state: last_ack\n");
					if(syn)
						continue;
					if(ack && match == 1){
						remove_connection(conn);
						i--;
						printk("[firewall] conn CLOSED!\n");
						ret = NF_ACCEPT;
						continue;
					}
					continue;
				}

		}	
	}
	return ret;
}

char* conn_str(){
	if(conn_size == 0)
		return NULL;
	char* str = kcalloc(conn_size , sizeof(char) * MAX_ROW_SIZE, GFP_ATOMIC);
	printk("[conn_di START %p]\n", str);
	//return NULL;
	conn_inc();
	if(!str){
		printk("[firewall] error in kcalloc in conn_string");
		return NULL;
	}
	char line[MAX_ROW_SIZE];
	line[0] = '\0';
	conn_t* conn;
	printk("FORLOOP %p\n", str);
	for(int i = 0; i < conn_size; i++){
		if(i > 0)
			str = strcat(str, "\n");
		conn = conn_list[i];
		sprintf(line, "%u %d %u %d %hhu", conn -> src_ip, conn -> src_port, conn -> dst_ip, conn -> dst_port, conn -> state);
		str = strcat(str, line);
		printk("forloop iteration %d %p\n", i, str);
	}
	printk("RETURN\n");
	return str;	
}

ssize_t conn_display(struct device *dev, struct device_attribute *attr, char *buf){
	printk("STATING\n");
	char* conns = conn_str();
	if(!conns){
		return 0;	
	}
	printk("[firew] %s %p\n", conns, conns);
	int ret = strlen(conns);
	strncpy(buf, conns, ret);
	kfree(conns);
	conn_dec();
	return ret;        	
}

void conn_setup(void){
	conn_list = kcalloc(DEFAULT_SIZE, sizeof(conn_t*), GFP_ATOMIC);
	conn_inc();	
	conn_arr_size = DEFAULT_SIZE;
	return;
}

void conn_clear(void){
	for(int i = 0; i < conn_size; i++){
		kfree(conn_list[i]);
		conn_dec();
	}
	kfree(conn_list);
	conn_dec();
	printk("[firewall] conn_allocnt = %d\n", allocnt);
	return;
}

int remove_connection(conn_t* conn){
	int idx = 0;
	int i = 0;
	for(i = 0; i < conn_size; i++, idx ++){
		if(conn_list[i] == conn){
			kfree(conn);
			conn_dec();
			idx --;
		}
		else{
			conn_list[idx] = conn_list[i];
		}
	}
	if(idx == i)
		return 1;

	conn_size --;
	if(conn_size == conn_arr_size/4 && conn_size > 10){
		conn_t** old_conn_list = conn_list;
		conn_list = kcalloc(conn_arr_size/2, sizeof(conn_t*), GFP_ATOMIC);
		conn_inc();
		for(int j = 0; j < conn_size; j++){
			conn_list[j] = old_conn_list[i];
		}
		conn_arr_size /= 2;
	}
	return 0;		
}

int add_new_connection(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port, state_t state){
	conn_t* conn = kcalloc(1, sizeof(conn_t), GFP_ATOMIC);
	if(!conn){
		return 1;
	}
	conn -> src_ip = src_ip;
	conn -> src_port = src_port;
	conn -> dst_ip =  dst_ip;
	conn -> dst_port = dst_port;
	conn -> state = state;
	if(conn_size == conn_arr_size){
		conn_t** old_conn_list = conn_list;
		conn_list = kcalloc(conn_arr_size * 2, sizeof(conn_t*), GFP_ATOMIC);
		conn_inc();
		conn_arr_size *= 2;	
		for(int i = 0; i < conn_size; i++){
			conn_list[i] = old_conn_list[i];
		}
			
	}
	conn_list[conn_size] = conn;
	conn_size ++; 
	return 0;
}

