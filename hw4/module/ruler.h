#include "fw.h"

int search_rule(int direction, unsigned int src_ip, unsigned int dst_ip, int src_port, int dst_port, int protocol, int ack);

rule_t* get(int idx);

int compare_ip(unsigned int ip1, unsigned int ip2, int mask);

ssize_t ruler_display(struct device *dev, struct device_attribute *attr, char *buf);

ssize_t ruler_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

rule_t* create_rule(int direction, unsigned int src_ip, unsigned int dst_ip, int src_port, int dst_port, int protocol, int ack, int action);
