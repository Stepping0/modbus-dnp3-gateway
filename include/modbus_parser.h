#ifndef MODBUS_PARSER_H
#define MODBUS_PARSER_H

#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

// Fonksiyon prototipleri
void print_hex(const u_char *data, int len);
void print_hex_string(const u_char *data, int len, char *out);
void write_json_entry(double timestamp, char *src_ip, int src_port, char *dst_ip, int dst_port,
                      int transaction_id, int function_code, const char *description,
                      const u_char *pdu_data, int pdu_len, const char *direction);
void process_packet(const struct pcap_pkthdr *header, const u_char *packet);

#endif