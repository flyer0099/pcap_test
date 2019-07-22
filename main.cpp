#include <pcap.h>
#include <stdio.h>

int total_length;
int temp;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    temp = 0;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    printf("Dmac : %02x:%02x:%02x:%02x:%x:%x\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    printf("Smac : %02x:%02x:%02x:%02x:%02x:%02x\n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    if(packet[12] == 0x08 && packet[13] == 0x00){
        printf("Sip : %u.%u.%u.%u\n",packet[26],packet[27],packet[28],packet[29]);
        printf("Dip : %u.%u.%u.%u\n",packet[30],packet[31],packet[32],packet[33]);
    }
    if(packet[23] == 0x06){
        printf("tcp.Sport : %d\n", (packet[34] << 8) | packet[35]);
        printf("tcp.Dport : %d\n", (packet[36] << 8) | packet[37]);
        if(packet[46] == 0x50) total_length = 14 + 20 + 20;
        else if(packet[46] == 0x60) total_length = 14 + 20 + 24;
        else if(packet[46] == 0xa0) total_length = 14 + 20 + 40;
        for(int i = total_length; i < total_length + 10; i++){
            if(packet[i] == 0x00) temp++;
        }
        if(temp < 3){
            printf("TCP data : ");
            for(int i = total_length; i < total_length + 10; i++){
                printf("%02x",packet[i]);
            }
            printf("\n");
        }
    }
  }

  pcap_close(handle);
  return 0;
}
