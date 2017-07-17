	
	 #include <pcap.h>
	 #include <stdio.h>

	 int main(int argc, char *argv[])
	 {
		pcap_t *handle;			/* Session handle */
		char *dev="ens33";			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "port 80";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr *header;	/* The header that pcap gives us */
		const u_char *pkt_data;		/* The actual packet */
	 	int i = 0;

		int chk;

		struct packet 
		{
			u_char des_mac[6];	//L2, ethernet des mac
			u_char src_mac[6];	//L2, ehternet src mac
			u_char src_ip[6];	//L3, ip src
			u_char des_ip[6];	//L3, ip des
			u_char src_port[2];	//L4, TCP src port
			u_char des_port[2];	//L4 TCP des port
			u_char chack_tcp[1];	//Is the TCP packet?
			u_char tcp_len[1];	// TCP Lenth (offset value)
			u_char data_start[999];	//L5, data
		}packet;


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
			if(chk = pcap_next_ex(handle, &header, &pkt_data) >0) //if, packet get faill, return else loop get packet 
			{


				int i;
			//	printf("Jacked a packet with length of [%d]\n", header->len);
				int leng = header->len;

				for(int j=0;j<=5;j++)
				{
					packet.des_mac[j] = *(pkt_data+j); //0byte ~ 5byte . des mac
					//*pkt_data++;
				}
				
				for(int j=6,i=0;j<=11;j++,i++)
				{
					
					packet.src_mac[i] = *(pkt_data+j); //6byte ~ 11byte. src mac
					//pkt_data++;
				}

				//pkt_data += 14;

				//printf("---%d---\n",*pkt_data );


				for(int j=26,i =0;j<=29;j++,i++)
				{

					packet.src_ip[i] = *(pkt_data+j); //26byte ~ 29byte. src ip
					//pkt_data++;

				}

				for(int j=30,i=0;j<=33;j++,i++)
				{

					packet.des_ip[i] = *(pkt_data+j); //30byte ~ 33byte. des ip
					//pkt_data++;

				}
				for(int j=34,i=0;j<=35;j++,i++)
				{

					packet.src_port[i] = *(pkt_data+j); //32byte~ 35byte. src port
					//pkt_data++;

				}

				for(int j=36,i=0;j<=37;j++,i++)
				{

					packet.des_port[i] = *(pkt_data+j); //36byte ~ 37byte des port
					//pkt_data++;

				}

				packet.chack_tcp[0] = *(pkt_data+23); //23 byte. if this value is 0x06(16), TCP packet


				if(0x06==(long)packet.chack_tcp[0])
				{
					printf("-----TCP Packet------\n"); //TCP packet marking
				}
				else 
				{
					break; //not TCP packet is drop
				}

				packet.tcp_len[0] = *(pkt_data+46)>>4; //tcp_lenth (offset) is 4bit. but, array tcp_len[0] is 1byte.
									//so, right shift 4bit result, 1st 4 bit zero padding

				for(int j = 34+(packet.tcp_len[0]*4),i=0 ;j<=header->len  ;j++,i++)
				{
					packet.data_start[i] = *(pkt_data+j); //network L3 end is 34byte. so, data start is 34byte + TCP header lenth
										//4byte unit .so *4

				}

/////////////////////////print////////////////////


				printf("eht.smac: ");
				for(int j=0;j<=5;j++)
				{
					printf("%02x:", (packet.des_mac[j])); //print des mac for 0x(16)
				}
				printf("\n");


				printf("eth.dmac: ");
				for(int j=0;j<=5;j++)
				{
					printf("%02x:", (packet.src_mac[j])); //print src mac for 0x(16)
				
				}
				printf("\n");

				printf("ip.sip: ");
				for(int j=0;j<=3;j++)
				{
					printf("%d.", (packet.src_ip[j])); //print src ip . for split 1byte to %d(10)
				
				}
				printf("\n");


				printf("ip.dip: ");
				for(int j=0;j<=3;j++)
				{
					printf("%d.", (packet.des_ip[j]));  //print des ip . for %d(10)
				
				}
				printf("\n");

				
				//printf("-----%x,%x---",packet.src_port[0],packet.des_port[1]);
				
				printf("tcp.sport: ");
				printf("%d\n", ( (packet.src_port[0]<<8) + (packet.src_port[1]) ));
				// if, src_port is e4da so, src_port[0] left shift zero padding.  e4 -> 0xe400(16)
								// + 0xda(16)
				
				printf("tcp.dport: ");
				printf("%d\n", ( (packet.des_port[0]<<8) + (packet.des_port[1]) ));
				
				//same algorithm for src port

				
				//print data
				printf("data:\n");
				printf("%s\n",packet.data_start);

			}

				//for(i=0; i <= leng; i++)
				//	printf("%x ", *(pkt_data + i) & 0xff);


			
			//if fail reseve packet, close handle and return
			else
			{
				pcap_close(handle);
				return (0);
			}
		}


		 //end. close handle and return


		pcap_close(handle);
		

		return(0);


	 
	 }
