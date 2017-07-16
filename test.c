	
	 #include <pcap.h>
	 #include <stdio.h>

	 int main(int argc, char *argv[])
	 {
		pcap_t *handle;			/* Session handle */
		char *dev;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "port 80";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr *header;	/* The header that pcap gives us */
		const u_char *pkt_data;		/* The actual packet */

		int chk;

		struct packet 
		{
			u_char des_mac[6];
			u_char src_mac[6];
		} packet;


		const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h);

		/* Define the device */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		/* Find the properties for the device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		}
		/* Open the session in promiscuous mode */
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}
		/* Compile and apply the filter */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		/* Grab a packet */
		//packet = pcap_next(handle, &header);
	//	int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, //
      //  				const u_char **pkt_data);

		//pcap_next_ex(handle, &header, &pkt_data);

		while(1)
		{
			if(chk = pcap_next_ex(handle, &header, &pkt_data) >0)
			{
				int i;
				printf("Jacked a packet with length of [%d]\n", header->len);
				int leng = header->len;

				for(int j=0;j<=5;j++)
				{
					packet.des_mac[j] = *(pkt_data);
					pkt_data++;
				}


				for(int j=0;j<=5;j++)
				{
					packet.src_mac[j] = *(pkt_data);
					pkt_data++;
				}



				for(int j=0;j<=5;j++)
				{
					printf("%02x:", (packet.des_mac[j]));
				}
				printf("\n");



				for(int j=0;j<=5;j++)
				{
					printf("%02x:", (packet.src_mac[j]));
				
				}
				printf("\n");

			}

				//for(i=0; i <= leng; i++)
				//	printf("%x ", *(pkt_data + i) & 0xff);


			

			else
			{
				pcap_close(handle);
				return (0);
			}
		}




		pcap_close(handle);
		

		return(0);


	 }