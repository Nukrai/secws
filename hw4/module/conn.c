#include "fw.h"
#include "conn.h"

void conn_inc(void){
	allocnt++;
}
void conn_dec(void){
	allocnt--;
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

	add_new_connection(src_ip, src_port, dst_ip, dst_port, CLOSED);
	add_new_connection(dst_ip, dst_port, src_ip, src_port, CLOSED);
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
	//TODO: add HTTP & FTP 	
	return 0;
}

unsigned int tcp_enforce(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port, int syn, int ack, int fin, int rst){
	conn_t* conn;
	int match;
	int no = 0;
	for(int i = 0 ; i < conn_size; ++i){
		printk("[firewall] checking conn number %d, src port %d, syn=%d, ack=%d, fin=%d, rst=%d\n",i, src_port,syn,ack,fin,rst);
		conn = conn_list[i];
		if((match = is_matching(src_ip, src_port, dst_ip, dst_port, syn, fin, rst, conn)) != 0){
			if(rst){
				remove_connection(conn);
				if(no > 0){
					return NF_ACCEPT;
				}
				// 
				no ++;
				continue;
			}
			switch(conn -> state){
				case CLOSED:
					printk("[firewall] conn state: CLOSED\n");
					if(syn && !ack && !fin){
						conn -> state = (match == 1 ? SYN_RCVD : SYN_SENT);
						return NF_ACCEPT;
					}
					continue;

				case SYN_SENT:
					printk("[firewall] conn state: SYN_SENT\n");
					if(syn && ack && !fin){
						conn -> state = ESTABLISHED;
						printk("[firewall] conn *changed* to EST\n");
						return NF_ACCEPT;
					}
					continue;

				case SYN_RCVD:
					printk("[firewall] conn state: SYN_RCVD\n");
					if(ack && !syn && !fin){
						conn -> state = ESTABLISHED;
						printk("[firewall] conn *changed* to EST\n");
						return NF_ACCEPT;
					}
					if(fin && match == 2){
						conn -> state = FIN_WAIT_1;
					}
					continue;

				case ESTABLISHED:
					printk("[firewall] conn state: EST\n");
					if(syn)
						return NF_DROP;
					if(fin){
						conn -> state = (match == 1 ? CLOSE_WAIT : FIN_WAIT_1);			
						printk("[firewall] conn *changed* to %s\n", ((match == 1) ? "CLOSE_WAIT" : "FIN_WAIT_1"));
						if(no > 0){
							return NF_ACCEPT;
						}
						no ++;
						continue;
					}
					return NF_ACCEPT;

				case FIN_WAIT_1:
					printk("[firewall] conn state: f1\n");
					if(syn)
						return NF_DROP;

					if(ack && fin && match == 1){
						remove_connection(conn);
						printk("[firewall] conn CLOSED!\n");
						return NF_ACCEPT;
					}
					if(fin && match == 2){
						return NF_ACCEPT; 
					}
					if(ack && match == 1){
						conn -> state = FIN_WAIT_2;
						printk("[firewall] conn *changed* to FIN_WAIT_2\n");
						return NF_ACCEPT;
					}
					if(fin && match == 1){
						conn -> state = CLOSING;
						printk("[firewall] conn *changed* to CLOSING\n");
					}
					return NF_ACCEPT;

				case FIN_WAIT_2:
					printk("[firewall] conn state: f2\n");
					if(syn || (!ack && match == 2))
						return NF_DROP;
					if(fin && match == 1){
						remove_connection(conn);
						printk("[firewall] conn CLOSED!\n");
						return NF_ACCEPT;
					}
					return NF_ACCEPT;

				case CLOSING:
					printk("[firewall] conn state: closing\n");
					if(syn)
						return NF_DROP;
					if(ack && !fin){
						if(match == 1){
							remove_connection(conn);
							printk("[firewall] conn CLOSED!\n");
						}
						return NF_ACCEPT;
					}
					return NF_DROP;
				case CLOSE_WAIT:
					printk("[firewall] conn state: close wait\n");
					if(syn || match == 1)
						return NF_DROP;
					if(ack){
						if(fin){
							conn -> state = LAST_ACK;
							printk("[firewall] conn *changed* to LASK_ACK\n");
						}
						return NF_ACCEPT;
						
					}
					if(fin){
						conn -> state = LAST_ACK;
						printk("[firewall] conn *changed* to LAST_ACK\n");
						return NF_ACCEPT;
					}
				case LAST_ACK:
					printk("[firewall] conn state: last_ack\n");
					if(syn)
						return NF_DROP;
					if(ack && match == 1){
						remove_connection(conn);
						printk("[firewall] conn CLOSED!\n");
						return NF_ACCEPT;
					}
					return NF_DROP;
				}

		}	
	}
	return NF_DROP;
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
	if(conn_size == conn_arr_size/4){
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

