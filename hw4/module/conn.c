#include "fw.h"
#include "conn.h"

void inc(void){
	allocnt++;
}
void dec(void){
	allocnt--;
}

int is_matching(unsigned int src_ip, int src_port, unsigned int dst_ip, int dst_port, conn_t* conn){
	if(src_ip == conn -> src_ip && src_port == conn -> src_port &&
	   dst_ip == conn -> dst_ip && dst_port == conn -> dst_port){
		return 1;
	}
	if(src_ip == conn -> dst_ip && src_port == conn -> dst_port &&
           dst_ip == conn -> src_ip && dst_port == conn -> src_port){
		return 2;
	}
	
	return 0;
}

unsigned int tcp_enforce(unsigned int src_ip, int port, unsigned int dst_ip, int port, int syn, int ack, int fin, int rst){
	conn_t* conn;
	int match;	
	for(int i = 0 ; i < conn_size; ++i){
		conn = conn_list[i];

		if((match= is_matching(src_ip, src_port, dst_ip, dst_port, conn)) != 0){
			if(rst){
				remove_connection(conn);
				return NF_ACCEPT;
			}
			switch(conn -> state){
				case SYN_SENT:
					if(syn && ack && !fin && match == 2){
						conn -> state = SYN_ACK_SENT;
						return NF_ACCEPT;
					}
					if(syn && match == 1)
						return NF_ACCEPT;
					return NF_DROP;
				case SYN_ACK_SENT:
					if(ack && !syn && !fin && match == 1){
						conn -> state = ESTABLISHED;
						return NF_ACCEPT;
					}
					if(syn && ack && !fin && match = 2)
						return NF_ACCEPT;
					return NF_DROP;

				case ESTABLISHED:
					if(syn):
						return NF_DROP;
					if(fin && match == 1){
						conn -> state = FIN_WAIT_1;
					}		
					if(fin && match == 2){
						conn  -> state = FIN_WAIT_2
					}
					return NF_ACCEPT;

				case FIN_WAIT_1:
					if(syn)
						return NF_DROP;
					if(match == 1 && !(fin && ack) && !ack)
						return NF_DROP;
					if(fin && match == 2){
						conn -> state = LAST_ACK_1; 
					}
					return NF_ACCEPT;
				case FIN_WAIT_2:
					if(syn)
						return NF_DROP;
					if(match == 2 && !ack && !fin)
						return NF_DROP;
					if(fin && match == 1){
						conn -> state = LAST_ACK_2;
					}
					return NF_ACCEPT;
				case LAST_ACK_1:
					if(ack && match == 1){
						remove_connection(conn);
						return NF_ACCEPT;
					}
					return NF_DROP;
				case LAST_ACK_2:
					if(ack && match  == 2){
						remove_connection(conn);
						return NF_ACCEPT;
					}
					return NF_DROP;
		}	
	}
	return NF_DROP;
}

char* conn_string(){
	char* ret = kcalloc(conn_size, sizeof(char) * MAX_ROW_SIZE, GFP_ATOMIC);
	inc();
	if(!ret){
		printk("[firewall] error in kcalloc in conn_string");
		return NULL;
	}
	char line[MAX_ROW_SIZE];
	conn_t* conn;
	for(int i = 0; i < conn_size; i++){
		if(i > 0)
			ret = strcat(ret, "\n");
		conn = conn_list[i];
		sprintf(line, "%u %d %u %d %hhu", conn -> src_ip, conn -> src_port, conn -> dst_ip, conn -> dst_port);
		ret = strcat(ret, line);
	}
	return ret;	
}

ssize_t conn_display(struct device *dev, struct device_attribute *attr, char *buf){
	char* conns = conn_str();
	int ret = sizeof(conns);
	strncpy(buf, conns, ret);
	free(conns);
	return ret;        	
}

void conn_setup(void){
	conn_lst = kcalloc(DEFAULT_SIZE, sizeof(conn_t*), GFP_ATOMIC);
	inc();	
	conn_size = DEFAULT_SIZE;
	return;
}

void conn_clear(void){
	for(int i = 0; i < conn_size; i++){
		kfree(conn_lst[i]);
		dec();
	}
	kfree(conn_lst);
	dec();
	printk("[firewall] conn_allocnt = %d\n", allocnt);
	return;
}
int remove_connection(conn_t* conn){
	int idx = 0;
	int i = 0;
	for(i = 0; i < conn_size; i++, idx ++){
		if(conn_list[i] == conn){
			kfree(conn);
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
		inc();
		for(int j = 0; j < conn_size; j++){
			conn_list[j] = old_conn_list[i];
		}
		conn_arr_size /= 2;
	}
	return 0;		
}

int add_new_connection(unsigned int src_ip, int src_port, unsigned int dst_ip, inr dst_port, state_t state){
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
		inc();
		conn_arr_size *= 2;	
		for(int i = 0; i < conn_size; i++){
			conn_list[i] = old_conn_list[i];
		}
			
	}
	conn_list[conn_size] = conn;
	conn_size ++; 
	return 0;
}
