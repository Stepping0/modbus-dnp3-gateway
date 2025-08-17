#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "../include/modbus_parser.h"

int packet_counter = 0;
FILE *json_file;
int wrote_any = 0;
static int first_json = 1;

/* -------------------- Pending Request Yapısı -------------------- */
typedef struct {
    uint32_t sip, dip;      // req src/dst IP (network order)
    uint16_t sport, dport;  // req src/dst port (host order)
    uint16_t txn;           // transaction_id
    uint16_t start, qty;    // request
    int      in_use;
} pending_t;

#define PENDING_MAX 256
static pending_t pend[PENDING_MAX];

static int key_match(const pending_t* p,
                     uint32_t sip, uint32_t dip,
                     uint16_t sport, uint16_t dport,
                     uint16_t txn)
{
    return p->in_use &&
           p->sip==sip && p->dip==dip &&
           p->sport==sport && p->dport==dport &&
           p->txn==txn;
}

static void pend_put(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport,
                     uint16_t txn, uint16_t start, uint16_t qty)
{
    for (int i=0;i<PENDING_MAX;i++){
        if (!pend[i].in_use){
            pend[i]=(pending_t){sip,dip,sport,dport,txn,start,qty,1};
            return;
        }
    }
}

static int pend_get_del(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport,
                        uint16_t txn, pending_t* out)
{
    for (int i=0;i<PENDING_MAX;i++){
        if (key_match(&pend[i], sip,dip,sport,dport,txn)){
            *out = pend[i];
            pend[i].in_use = 0;
            return 1;
        }
    }
    return 0;
}

/* -------------------- Yardımcı Fonksiyonlar -------------------- */
void print_hex(const u_char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
}

void print_hex_string(const u_char *data, int len, char *out) {
    if (len <= 0) {                  
        out[0] = '\0';
        return;
    }
    for (int i = 0; i < len; i++) {
        sprintf(out + i * 3, "%02X ", data[i]);
    }
    out[len * 3 - 1] = '\0';
}

static void write_regs_json(uint8_t fc, uint16_t start, const uint16_t* vals, int n)
{
    if (!first_json) fprintf(json_file, ",\n");
    first_json = 0;

    fprintf(json_file,
        "  { \"record_type\": \"values\", \"direction\": \"response\", "
        "\"function_code\": %u, \"start_address\": %u, \"values\": [",
        fc, start);
    for (int i=0;i<n;i++) fprintf(json_file, "%s%u", i?", ":"", vals[i]);
    fprintf(json_file, "] }");
}

void write_json_entry(double timestamp, char *src_ip, int src_port, char *dst_ip, int dst_port,
                      int transaction_id, int function_code, const char *description,
                      const u_char *pdu_data, int pdu_len, const char *direction) {

    if (!first_json) fprintf(json_file, ",\n");
    first_json = 0;

    char hex_str[1024] = {0};
    print_hex_string(pdu_data, pdu_len, hex_str);

    fprintf(json_file,
            "  {\n"
            "    \"direction\": \"%s\",\n"
            "    \"packet_number\": %d,\n"
            "    \"timestamp\": %.6f,\n"
            "    \"src_ip\": \"%s\",\n"
            "    \"src_port\": %d,\n"
            "    \"dst_ip\": \"%s\",\n"
            "    \"dst_port\": %d,\n"
            "    \"transaction_id\": %d,\n"
            "    \"function_code\": %d,\n"
            "    \"description\": \"%s\",\n"
            "    \"raw_pdu\": \"%s\"\n"
            "  }\n",
            direction,
            packet_counter, timestamp, src_ip, src_port, dst_ip, dst_port,
            transaction_id, function_code, description, hex_str);
}


/* -------------------- Paket İşleme -------------------- */
void process_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    
    if (header->caplen < 54) return;

    const u_char *ip_header = packet + 14;
    int ip_header_len = (ip_header[0] & 0x0F) * 4;
    if (14 + ip_header_len + 20 > (int)header->caplen) return;

    const u_char *tcp_header = ip_header + ip_header_len;
    int tcp_header_len = ((tcp_header[12] & 0xF0) >> 4) * 4;
    if (tcp_header_len < 20) return;
    if (14 + ip_header_len + tcp_header_len > (int)header->caplen) return;

    const u_char *modbus_data = tcp_header + tcp_header_len;
    int modbus_data_len = header->caplen - (14 + ip_header_len + tcp_header_len);

    uint16_t src_port = ntohs(*(uint16_t *)(tcp_header));
    uint16_t dst_port = ntohs(*(uint16_t *)(tcp_header + 2));
    
    if (src_port != 502 && dst_port != 502) return;

    packet_counter++;

    uint16_t transaction_id = ntohs(*(uint16_t *)(modbus_data));
    uint16_t protocol_id    = ntohs(*(uint16_t *)(modbus_data + 2));
    uint16_t length         = ntohs(*(uint16_t *)(modbus_data + 4));
    uint8_t  unit_id        = *(modbus_data + 6);
    uint8_t  function_code  = *(modbus_data + 7);

    struct in_addr src_ip, dst_ip;
    memcpy(&src_ip, ip_header + 12, 4);
    memcpy(&dst_ip, ip_header + 16, 4);

    /* ---- İSTEK KAYDI ---- */
    if (dst_port == 502 && (function_code == 0x03 || function_code == 0x04)) {
        if (modbus_data_len >= 12) {
            uint16_t start = ntohs(*(uint16_t *)(modbus_data + 8));
            uint16_t qty   = ntohs(*(uint16_t *)(modbus_data + 10));
            pend_put(src_ip.s_addr, dst_ip.s_addr, src_port, dst_port, transaction_id, start, qty);
        }
    }

    /* ---- YANIT KAYDI ---- */
    if (src_port == 502 && (function_code == 0x03 || function_code == 0x04)) {
        if (modbus_data_len >= 9) {
            uint8_t byte_count = *(modbus_data + 8);
            int regs = byte_count / 2;
            const u_char* data = modbus_data + 9;

            pending_t p;
            if (pend_get_del(dst_ip.s_addr, src_ip.s_addr, dst_port, src_port, transaction_id, &p)) {
                int n = regs;
                if (n > 256) n = 256;
                uint16_t vals[256];
                for (int i=0;i<n;i++) {
                    vals[i] = (data[2*i] << 8) | data[2*i+1];
                }
                write_regs_json(function_code, p.start, vals, n);
            }
        }
    }

    if (protocol_id != 0) return;

    printf("┌──────── Paket #%d ────────\n", packet_counter);
    printf("│ Zaman: %.6f\n", header->ts.tv_sec + header->ts.tv_usec / 1000000.0);
    printf("│ Toplam uzunluk: %d bytes\n", header->len);
    printf("│ Modbus veri uzunluğu: %d bytes\n", length + 6);

    printf("│ [MODBUS/TCP] %s:%d -> %s:%d\n", inet_ntoa(src_ip), src_port, inet_ntoa(dst_ip), dst_port);

    printf("│ MBAP Header:\n");
    printf("│   Transaction ID: %d (0x%04X)\n", transaction_id, transaction_id);
    printf("│   Protocol ID   : %d (Modbus)\n", protocol_id);
    printf("│   Length        : %d bytes\n", length);
    printf("│   Unit ID       : %d\n", unit_id);

    printf("│ PDU:\n");
    printf("│   Function Code : 0x%02X (%d) - ", function_code, function_code);

    const char *desc = "UNKNOWN";
    switch (function_code) {
         case 0x01:
        desc = "READ_COILS";
        printf("READ_COILS\n");
        break;
    case 0x02:
        desc = "READ_DISCRETE_INPUTS";
        printf("READ_DISCRETE_INPUTS\n");
        break;
    case 0x03:
        desc = "READ_HOLDING_REGISTERS";
        printf("READ_HOLDING_REGISTERS\n");
        uint16_t start_addr = ntohs(*(uint16_t *)(modbus_data + 8));
        uint16_t qty = ntohs(*(uint16_t *)(modbus_data + 10));
        printf("│   Fonksiyon    : Holding register değerlerini oku\n");
        printf("│   Request      : Start Address: %u, Quantity: %u registers\n", start_addr, qty);
        break;
    case 0x04:
        desc = "READ_INPUT_REGISTERS";
        printf("READ_INPUT_REGISTERS\n");
        break;
    case 0x05:
        desc = "WRITE_SINGLE_COIL";
        printf("WRITE_SINGLE_COIL\n");
        break;
    case 0x06:
        desc = "WRITE_SINGLE_REGISTER";
        printf("WRITE_SINGLE_REGISTER\n");
        break;
    case 0x0F:
        desc = "WRITE_MULTIPLE_COILS";
        printf("WRITE_MULTIPLE_COILS\n");
        break;
    case 0x10:
        desc = "WRITE_MULTIPLE_REGISTERS";
        printf("WRITE_MULTIPLE_REGISTERS\n");
        break;
    default:
        printf("Bilinmeyen işlem\n");
        break;
    }

    printf("│   Raw PDU      : ");
    print_hex(modbus_data + 7, modbus_data_len - 7);
    printf("\n└───────────────────────────────\n\n");

    double ts = header->ts.tv_sec + header->ts.tv_usec / 1000000.0;
    char sip[16], dip[16];
    snprintf(sip, sizeof(sip), "%s", inet_ntoa(src_ip));
    snprintf(dip, sizeof(dip), "%s", inet_ntoa(dst_ip));

    int pdu_len = modbus_data_len - 7;
    if (pdu_len < 0) pdu_len = 0;

    const char *direction = (src_port == 502) ? "response" : "request";

    write_json_entry(
        ts, sip, src_port, dip, dst_port,
        transaction_id, function_code, desc,
        modbus_data + 7, pdu_len, direction
    );
}

/* -------------------- main -------------------- */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Kullanım: %s dosya.pcapng\n", argv[0]);
        return 1;
    }

    char *pcap_file = argv[1];
    char *json_output = "../json_kayit/modbus_output.json";

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Hata: %s\n", errbuf);
        return 2;
    }

    json_file = fopen(json_output, "w");
    if (!json_file) {
        perror("JSON dosyası açılamadı");
        return 1;
    }

    fprintf(json_file, "[\n");

    struct pcap_pkthdr *header;
    const u_char *packet;
    int res;
    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) continue;
        process_packet(header, packet);
    }

    fprintf(json_file, "\n]\n");

    fclose(json_file);
    pcap_close(handle);

    printf("JSON çıktısı başarıyla oluşturuldu: modbus_output.json\n");
    return 0;
}
