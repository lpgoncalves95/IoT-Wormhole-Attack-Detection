/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include "contiki.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include "net/uip.h"
#include "net/uip-ds6.h"
#include "net/uip-udp-packet.h"
#include "sys/ctimer.h"
#include "net/tcpip.c"
#include "net/mac/sicslowmac.c"
/*adicionei botao*/
#include "dev/button-sensor.h"
#include "powertrace.h"
#ifdef WITH_COMPOWER
#include "powertrace.h"
#endif
#include <stdio.h>
#include <string.h>

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

#define UDP_EXAMPLE_ID  190

#define DEBUG DEBUG_PRINT
#include "net/uip-debug.h"

#ifndef PERIOD
#define PERIOD 60
#endif

#define START_INTERVAL		(15 * CLOCK_SECOND)
#define SEND_INTERVAL		(PERIOD * CLOCK_SECOND)
#define SEND_TIME		(random_rand() % (SEND_INTERVAL))
#define MAX_PAYLOAD_LEN		30

int inicio=0;
static struct uip_udp_conn *client_conn;
static uip_ipaddr_t server_ipaddr;


/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  char *str;

  if(uip_newdata()) {
    str = uip_appdata;
    str[uip_datalen()] = '\0';
    printf("DATA recv '%s'\n", str);
  }
}
/*---------------------------------------------------------------------------*/
static void
send_packett(void *ptr)
{
  static int seq_id;
  char buf[MAX_PAYLOAD_LEN];

  seq_id++;
  printf("DATA send to %d 'Hello %d'\n",
         server_ipaddr.u8[sizeof(server_ipaddr.u8) - 1], seq_id);
  sprintf(buf, "0:000:000", seq_id);
  uip_udp_packet_sendto(client_conn, buf, strlen(buf),
                        &server_ipaddr, UIP_HTONS(UDP_SERVER_PORT));
}
/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Client IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
      /* hack to make address "final" */
      if (state == ADDR_TENTATIVE) {
	uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
set_global_address(void)
{
  uip_ipaddr_t ipaddr;

  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

/* The choice of server address determines its 6LoPAN header compression.
 * (Our address will be compressed Mode 3 since it is derived from our link-local address)
 * Obviously the choice made here must also be selected in udp-server.c.
 *
 * For correct Wireshark decoding using a sniffer, add the /64 prefix to the 6LowPAN protocol preferences,
 * e.g. set Context 0 to aaaa::.  At present Wireshark copies Context/128 and then overwrites it.
 * (Setting Context 0 to aaaa::1111:2222:3333:4444 will report a 16 bit compressed address of aaaa::1111:22ff:fe33:xxxx)
 *
 * Note the IPCMV6 checksum verification depends on the correct uncompressed addresses.
 */
 
#if 0
/* Mode 1 - 64 bits inline */
   uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
#elif 1
/* Mode 2 - 16 bits inline */
  uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0, 0x00ff, 0xfe00, 1);
#else
/* Mode 3 - derived from server link-local (MAC) address */
  uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0x0250, 0xc2ff, 0xfea8, 0xcd1a); //redbee-econotag
#endif

/* tabela geral*/

  tabela_geral = malloc(sizeof(no_geral)*numero_de_nos);
  /*varia com a implementacao*/
  uip_ipaddr_t ipaddr1;
  uip_ip6addr(&ipaddr1, 0xfe80, 0, 0, 0, 0x0212, 0x7401, 0x0001, 0x0101);//1
  uip_ipaddr_t ipaddr2;
  uip_ip6addr(&ipaddr2, 0xfe80, 0, 0, 0, 0x0212, 0x7402, 0x0002, 0x0202);//2
  uip_ipaddr_t ipaddr3;
  uip_ip6addr(&ipaddr3, 0xfe80, 0, 0, 0, 0x0212, 0x7403, 0x0003, 0x0303);//3
  uip_ipaddr_t ipaddr4;
  uip_ip6addr(&ipaddr4, 0xfe80, 0, 0, 0, 0x0212, 0x7404, 0x0004, 0x0404);//4
  uip_ipaddr_t ipaddr5;
  uip_ip6addr(&ipaddr5, 0xfe80, 0, 0, 0, 0x0212, 0x7405, 0x0005, 0x0505);//5
  uip_ipaddr_t ipaddr6;
  uip_ip6addr(&ipaddr6, 0xfe80, 0, 0, 0, 0x0212, 0x7406, 0x0006, 0x0606);//6
  uip_ipaddr_t ipaddr7;
  uip_ip6addr(&ipaddr7, 0xfe80, 0, 0, 0, 0x0212, 0x7407, 0x0007, 0x0707);//7
  uip_ipaddr_t ipaddr8;
  uip_ip6addr(&ipaddr8, 0xfe80, 0, 0, 0, 0x0212, 0x7408, 0x0008, 0x0808);//8
  uip_ipaddr_t ipaddr9;
  uip_ip6addr(&ipaddr9, 0xfe80, 0, 0, 0, 0x0212, 0x7409, 0x0009, 0x0909);//9
  uip_ipaddr_t ipaddr10;
  uip_ip6addr(&ipaddr10, 0xfe80, 0, 0, 0, 0x0212, 0x740a, 0x000a, 0x0a0a);//10
  uip_ipaddr_t ipaddr11;
  uip_ip6addr(&ipaddr11, 0xfe80, 0, 0, 0, 0x0212, 0x740b, 0x000b, 0x0b0b);//11

// para a simulacao com 10 nos
  uip_ipaddr_t ipaddr12;
  uip_ip6addr(&ipaddr12, 0xfe80, 0, 0, 0, 0x0212, 0x740c, 0x000c, 0x0c0c);//12
  uip_ipaddr_t ipaddr13;
  uip_ip6addr(&ipaddr13, 0xfe80, 0, 0, 0, 0x0212, 0x740d, 0x000d, 0x0d0d);//13
  uip_ipaddr_t ipaddr14;
  uip_ip6addr(&ipaddr14, 0xfe80, 0, 0, 0, 0x0212, 0x740e, 0x000e, 0x0e0e);//14
  uip_ipaddr_t ipaddr15;
  uip_ip6addr(&ipaddr15, 0xfe80, 0, 0, 0, 0x0212, 0x740f, 0x000f, 0x0f0f);//15
  uip_ipaddr_t ipaddr16;
  uip_ip6addr(&ipaddr16, 0xfe80, 0, 0, 0, 0x0212, 0x7410, 0x0010, 0x1010);//16
  uip_ipaddr_t ipaddr17;
  uip_ip6addr(&ipaddr17, 0xfe80, 0, 0, 0, 0x0212, 0x7411, 0x0011, 0x1111);//17
  uip_ipaddr_t ipaddr18;
  uip_ip6addr(&ipaddr18, 0xfe80, 0, 0, 0, 0x0212, 0x7412, 0x0012, 0x1212);//18
  uip_ipaddr_t ipaddr19;
  uip_ip6addr(&ipaddr19, 0xfe80, 0, 0, 0, 0x0212, 0x7413, 0x0013, 0x1313);//19
  uip_ipaddr_t ipaddr20;
  uip_ip6addr(&ipaddr20, 0xfe80, 0, 0, 0, 0x0212, 0x7414, 0x0014, 0x1414);//20
  uip_ipaddr_t ipaddr21;
  uip_ip6addr(&ipaddr21, 0xfe80, 0, 0, 0, 0x0212, 0x7415, 0x0015, 0x1515);//21
// para a simulacao com 20 nos
  uip_ipaddr_t ipaddr22;
  uip_ip6addr(&ipaddr22, 0xfe80, 0, 0, 0, 0x0212, 0x7416, 0x0016, 0x1616);//22
  uip_ipaddr_t ipaddr23;
  uip_ip6addr(&ipaddr23, 0xfe80, 0, 0, 0, 0x0212, 0x7417, 0x0017, 0x1717);//23
  uip_ipaddr_t ipaddr24;
  uip_ip6addr(&ipaddr24, 0xfe80, 0, 0, 0, 0x0212, 0x7418, 0x0018, 0x1818);//24
  uip_ipaddr_t ipaddr25;
  uip_ip6addr(&ipaddr25, 0xfe80, 0, 0, 0, 0x0212, 0x7419, 0x0019, 0x1919);//25
  uip_ipaddr_t ipaddr26;
  uip_ip6addr(&ipaddr26, 0xfe80, 0, 0, 0, 0x0212, 0x741a, 0x001a, 0x1a1a);//26
  uip_ipaddr_t ipaddr27;
  uip_ip6addr(&ipaddr27, 0xfe80, 0, 0, 0, 0x0212, 0x741b, 0x001b, 0x1b1b);//27
  uip_ipaddr_t ipaddr28;
  uip_ip6addr(&ipaddr28, 0xfe80, 0, 0, 0, 0x0212, 0x741c, 0x001c, 0x1c1c);//28
  uip_ipaddr_t ipaddr29;
  uip_ip6addr(&ipaddr29, 0xfe80, 0, 0, 0, 0x0212, 0x741d, 0x001d, 0x1d1d);//29
  uip_ipaddr_t ipaddr30;
  uip_ip6addr(&ipaddr30, 0xfe80, 0, 0, 0, 0x0212, 0x741e, 0x001e, 0x1e1e);//30
  uip_ipaddr_t ipaddr31;
  uip_ip6addr(&ipaddr31, 0xfe80, 0, 0, 0, 0x0212, 0x741f, 0x001f, 0x1f1f);//31
/* para a simulacao com 30 nos*/

  /*tabela_geral[0].ip = ipaddr2;//para 10 nos
  tabela_geral[0].ip1 = ipaddr1;
  tabela_geral[0].distancia = 11;

  tabela_geral[1].ip = ipaddr3;
  tabela_geral[1].ip1 = ipaddr1;
  tabela_geral[1].distancia = 12;

  tabela_geral[2].ip = ipaddr4;
  tabela_geral[2].ip1 = ipaddr2;
  tabela_geral[2].distancia = 14;

  tabela_geral[3].ip = ipaddr5;
  tabela_geral[3].ip1 = ipaddr2;
  tabela_geral[3].distancia = 10;

  tabela_geral[4].ip = ipaddr6;
  tabela_geral[4].ip1 = ipaddr3;
  tabela_geral[4].distancia = 18;

  tabela_geral[5].ip = ipaddr7;
  tabela_geral[5].ip1 = ipaddr6;
  tabela_geral[5].distancia = 16;

  tabela_geral[6].ip = ipaddr8;
  tabela_geral[6].ip1 = ipaddr5;
  tabela_geral[6].distancia = 10;

  tabela_geral[7].ip = ipaddr9;
  tabela_geral[7].ip1 = ipaddr7;
  tabela_geral[7].distancia = 7;

  tabela_geral[8].ip = ipaddr10;
  tabela_geral[8].ip1 = ipaddr5;
  tabela_geral[8].distancia = 15;

  tabela_geral[9].ip = ipaddr11;
  tabela_geral[9].ip1 = ipaddr7;
  tabela_geral[9].distancia = 8;*/

  /*tabela_geral[0].ip = ipaddr2;//para 20 nos
  tabela_geral[0].ip1 = ipaddr1;
  tabela_geral[0].distancia = 10;

  tabela_geral[1].ip = ipaddr3;
  tabela_geral[1].ip1 = ipaddr1;
  tabela_geral[1].distancia = 11;

  tabela_geral[2].ip = ipaddr4;
  tabela_geral[2].ip1 = ipaddr2;
  tabela_geral[2].distancia = 7;

  tabela_geral[3].ip = ipaddr5;
  tabela_geral[3].ip1 = ipaddr2;
  tabela_geral[3].distancia = 4;

  tabela_geral[4].ip = ipaddr6;
  tabela_geral[4].ip1 = ipaddr3;
  tabela_geral[4].distancia = 4;

  tabela_geral[5].ip = ipaddr7;
  tabela_geral[5].ip1 = ipaddr6;
  tabela_geral[5].distancia = 14;

  tabela_geral[6].ip = ipaddr8;
  tabela_geral[6].ip1 = ipaddr5;
  tabela_geral[6].distancia = 8;

  tabela_geral[7].ip = ipaddr9;
  tabela_geral[7].ip1 = ipaddr7;
  tabela_geral[7].distancia = 13;

  tabela_geral[8].ip = ipaddr10;
  tabela_geral[8].ip1 = ipaddr4;
  tabela_geral[8].distancia = 6;

  tabela_geral[9].ip = ipaddr11;
  tabela_geral[9].ip1 = ipaddr8;
  tabela_geral[9].distancia = 11;

  tabela_geral[10].ip = ipaddr12;
  tabela_geral[10].ip1 = ipaddr2;
  tabela_geral[10].distancia = 9;

  tabela_geral[11].ip = ipaddr13;
  tabela_geral[11].ip1 = ipaddr3;
  tabela_geral[11].distancia = 5;

  tabela_geral[12].ip = ipaddr14;
  tabela_geral[12].ip1 = ipaddr10;
  tabela_geral[12].distancia = 15;

  tabela_geral[13].ip = ipaddr15;
  tabela_geral[13].ip1 = ipaddr19;
  tabela_geral[13].distancia = 2;

  tabela_geral[14].ip = ipaddr16;
  tabela_geral[14].ip1 = ipaddr6;
  tabela_geral[14].distancia = 6;

  tabela_geral[15].ip = ipaddr17;
  tabela_geral[15].ip1 = ipaddr16;
  tabela_geral[15].distancia = 4;

  tabela_geral[16].ip = ipaddr18;
  tabela_geral[16].ip1 = ipaddr4;
  tabela_geral[16].distancia = 7;

  tabela_geral[17].ip = ipaddr19;
  tabela_geral[17].ip1 = ipaddr10;
  tabela_geral[17].distancia = 16;

  tabela_geral[18].ip = ipaddr20;
  tabela_geral[18].ip1 = ipaddr9;
  tabela_geral[18].distancia = 5;

  tabela_geral[19].ip = ipaddr21;
  tabela_geral[19].ip1 = ipaddr8;
  tabela_geral[19].distancia = 10;*/

  tabela_geral[0].ip = ipaddr2;//para 30 nos
  tabela_geral[0].ip1 = ipaddr1;
  tabela_geral[0].distancia = 12;

  tabela_geral[1].ip = ipaddr3;
  tabela_geral[1].ip1 = ipaddr1;
  tabela_geral[1].distancia = 14;

  tabela_geral[2].ip = ipaddr4;
  tabela_geral[2].ip1 = ipaddr2;
  tabela_geral[2].distancia = 17;

  tabela_geral[3].ip = ipaddr5;
  tabela_geral[3].ip1 = ipaddr2;
  tabela_geral[3].distancia = 15;

  tabela_geral[4].ip = ipaddr6;
  tabela_geral[4].ip1 = ipaddr3;
  tabela_geral[4].distancia = 12;

  tabela_geral[5].ip = ipaddr7;
  tabela_geral[5].ip1 = ipaddr6;
  tabela_geral[5].distancia = 7;

  tabela_geral[6].ip = ipaddr8;
  tabela_geral[6].ip1 = ipaddr5;
  tabela_geral[6].distancia = 10;

  tabela_geral[7].ip = ipaddr9;
  tabela_geral[7].ip1 = ipaddr7;
  tabela_geral[7].distancia = 6;

  tabela_geral[8].ip = ipaddr10;
  tabela_geral[8].ip1 = ipaddr4;
  tabela_geral[8].distancia = 13;

  tabela_geral[9].ip = ipaddr11;
  tabela_geral[9].ip1 = ipaddr7;
  tabela_geral[9].distancia = 7;

  tabela_geral[10].ip = ipaddr12;
  tabela_geral[10].ip1 = ipaddr2;
  tabela_geral[10].distancia = 11;

  tabela_geral[11].ip = ipaddr13;
  tabela_geral[11].ip1 = ipaddr10;
  tabela_geral[11].distancia = 11;

  tabela_geral[12].ip = ipaddr14;
  tabela_geral[12].ip1 = ipaddr10;
  tabela_geral[12].distancia = 10;

  tabela_geral[13].ip = ipaddr15;
  tabela_geral[13].ip1 = ipaddr19;
  tabela_geral[13].distancia = 8;

  tabela_geral[14].ip = ipaddr16;
  tabela_geral[14].ip1 = ipaddr6;
  tabela_geral[14].distancia = 9;

  tabela_geral[15].ip = ipaddr17;
  tabela_geral[15].ip1 = ipaddr16;
  tabela_geral[15].distancia = 11;

  tabela_geral[16].ip = ipaddr18;
  tabela_geral[16].ip1 = ipaddr4;
  tabela_geral[16].distancia = 12;

  tabela_geral[17].ip = ipaddr19;
  tabela_geral[17].ip1 = ipaddr28;
  tabela_geral[17].distancia = 8;

  tabela_geral[18].ip = ipaddr20;
  tabela_geral[18].ip1 = ipaddr9;
  tabela_geral[18].distancia = 9;

  tabela_geral[19].ip = ipaddr21;
  tabela_geral[19].ip1 = ipaddr8;
  tabela_geral[19].distancia = 13;

  tabela_geral[20].ip = ipaddr22;
  tabela_geral[20].ip1 = ipaddr19;
  tabela_geral[20].distancia = 9;

  tabela_geral[21].ip = ipaddr23;
  tabela_geral[21].ip1 = ipaddr28;
  tabela_geral[21].distancia = 6;

  tabela_geral[22].ip = ipaddr24;
  tabela_geral[22].ip1 = ipaddr17;
  tabela_geral[22].distancia = 10;

  tabela_geral[23].ip = ipaddr25;
  tabela_geral[23].ip1 = ipaddr3;
  tabela_geral[23].distancia = 11;

  tabela_geral[24].ip = ipaddr26;
  tabela_geral[24].ip1 = ipaddr6;
  tabela_geral[24].distancia = 5;

  tabela_geral[25].ip = ipaddr27;
  tabela_geral[25].ip1 = ipaddr26;
  tabela_geral[25].distancia = 7;

  tabela_geral[26].ip = ipaddr28;
  tabela_geral[26].ip1 = ipaddr30;
  tabela_geral[26].distancia = 7;

  tabela_geral[27].ip = ipaddr29;
  tabela_geral[27].ip1 = ipaddr27;
  tabela_geral[27].distancia = 9;

  tabela_geral[28].ip = ipaddr30;
  tabela_geral[28].ip1 = ipaddr2;
  tabela_geral[28].distancia = 9;

  tabela_geral[29].ip = ipaddr31;
  tabela_geral[29].ip1 = ipaddr23;
  tabela_geral[29].distancia = 9;


  no_local.ip = tabela_geral[uip_ds6_if.addr_list[2].ipaddr.u8[sizeof(uip_ds6_if.addr_list[2].ipaddr.u8)-1]-2].ip1;
  no_local.distancia = tabela_geral[uip_ds6_if.addr_list[2].ipaddr.u8[sizeof(uip_ds6_if.addr_list[2].ipaddr.u8)-1]-2].distancia;

/*-------------*/

}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic, inicializacao;
  static struct ctimer backoff_timer;
#if WITH_COMPOWER
  static int print = 0;
#endif

  PROCESS_BEGIN();
  powertrace_start(CLOCK_SECOND*60);

/*ativar sensores*/
  SENSORS_ACTIVATE(button_sensor);
/*---------------*/

  PROCESS_PAUSE();

  set_global_address();
  
  PRINTF("UDP client process started\n");
  printf("RTIMER %u\n",RTIMER_SECOND);

  print_local_addresses();

  /* new connection with remote host */
  client_conn = udp_new(NULL, UIP_HTONS(UDP_SERVER_PORT), NULL); 
  if(client_conn == NULL) {
    PRINTF("No UDP connection available, exiting the process!\n");
    PROCESS_EXIT();
  }
  udp_bind(client_conn, UIP_HTONS(UDP_CLIENT_PORT)); 

  PRINTF("Created a connection with the server ");
  PRINT6ADDR(&client_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n",
	UIP_HTONS(client_conn->lport), UIP_HTONS(client_conn->rport));

#if WITH_COMPOWER
  powertrace_sniff(POWERTRACE_ON);
#endif
/* IDS - Inicializacao das estruturas auxiliares cliente*/
  etimer_set (&inicializacao,30*CLOCK_SECOND);

  PROCESS_WAIT_UNTIL(etimer_expired(&inicializacao));
 
  numero_de_vizinhos = uip_ds6_nbr_num();

  if (inicio==0){
          int v=0;
          tabela_vizinhos=malloc(sizeof(no_vizinho)*numero_de_vizinhos);
          uip_ds6_nbr_t *nbr = NULL;
	  for (nbr = nbr_table_head(ds6_neighbors);nbr!=NULL; nbr = nbr_table_next(ds6_neighbors, nbr)){
	  	tabela_vizinhos[v].ip=nbr->ipaddr;
		v++;
	  }
	  inicio=1;
	  printf("\nIDS - Tabela de distancias local definida\n");
  }

  
  
/*------------------------------------------------------*/

  etimer_set(&periodic, SEND_INTERVAL);
  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    }
    /*ativacao do botao*/
    else if(ev==sensors_event && data==&button_sensor){
       
       if(i_am_attacker==0){
         i_am_attacker=1;
	 attack_on=1;
         printf("Ataque ativado\n");
       }
       else if(i_am_attacker==1){
	 i_am_attacker=0;
	 attack_on=0;
	 printf("Ataque desativado\n");
	}
    }
    
    if(etimer_expired(&periodic)) {
      etimer_reset(&periodic);
      if (i_am_attacker==0){
         ctimer_set(&backoff_timer, SEND_TIME, send_packett, NULL);
      }

#if WITH_COMPOWER
      if (print == 0) {
	powertrace_print("#P");
      }
      if (++print == 3) {
	print = 0;
      }
#endif

    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
