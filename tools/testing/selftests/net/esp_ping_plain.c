// SPDX-License-Identifier: GPL-2.0
/*
 * esp_ping_plain - selftest for plain ESP ping (draft-ietf-ipsecme-esp-ping-01)
 *
 * Sends an ESP echo request (SPI=7) to loopback and validates that the kernel
 * replies with an ESP echo response (SPI=8).
 *
 * Requires CAP_NET_RAW. Run inside a network namespace with loopback up.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "kselftest.h"

#ifndef IPPROTO_ESP
#define IPPROTO_ESP		50
#endif
#define ESP_PING_SPI_REQUEST	7
#define ESP_PING_SPI_REPLY	8
#define ESP_ECHO_REQUEST	2
#define ESP_ECHO_RESPONSE	3
#define DATA_LEN		16
#define RECV_TIMEOUT_SEC	5

struct esp_hdr {
	uint32_t spi;
	uint32_t seq_no;
};

struct esp_echo_hdr {
	uint8_t  sub_type;
	uint8_t  flags;
	uint16_t data_len;
	uint16_t id;
	uint16_t seq;
};

struct esp_ping_pkt {
	struct iphdr        iph;
	struct esp_hdr      esph;
	struct esp_echo_hdr echo;
	uint8_t             data[DATA_LEN];
};

int main(void)
{
	struct esp_ping_pkt pkt;
	struct sockaddr_in dst = {
		.sin_family      = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	uint8_t buf[sizeof(struct iphdr) + sizeof(struct esp_hdr) +
		    sizeof(struct esp_echo_hdr) + DATA_LEN + 64];
	struct iphdr        *riph;
	struct esp_hdr      *resph;
	struct esp_echo_hdr *reh;
	struct timeval tv = { .tv_sec = RECV_TIMEOUT_SEC };
	uint16_t myid = (uint16_t)getpid();
	int sock, one = 1, ret;
	ssize_t n;

	ksft_print_header();
	ksft_set_plan(4);

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ESP);
	if (sock < 0) {
		if (errno == EPERM || errno == EACCES)
			ksft_exit_skip("need CAP_NET_RAW\n");
		ksft_exit_fail_msg("socket: %s\n", strerror(errno));
	}

	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	/* build request */
	memset(&pkt, 0, sizeof(pkt));
	pkt.iph.version  = 4;
	pkt.iph.ihl      = 5;
	pkt.iph.ttl      = 64;
	pkt.iph.protocol = IPPROTO_ESP;
	pkt.iph.saddr    = htonl(INADDR_LOOPBACK);
	pkt.iph.daddr    = htonl(INADDR_LOOPBACK);
	pkt.iph.tot_len  = htons(sizeof(pkt));

	pkt.esph.spi    = htonl(ESP_PING_SPI_REQUEST);
	pkt.esph.seq_no = htonl(1);

	pkt.echo.sub_type = ESP_ECHO_REQUEST;
	pkt.echo.flags    = 0;
	pkt.echo.data_len = htons(DATA_LEN);
	pkt.echo.id       = htons(myid);
	pkt.echo.seq      = htons(1);
	memset(pkt.data, 0x42, DATA_LEN);

	ret = sendto(sock, &pkt, sizeof(pkt), 0,
		     (struct sockaddr *)&dst, sizeof(dst));
	ksft_test_result(ret == (int)sizeof(pkt), "send ESP echo request (SPI=7)\n");
	if (ret != (int)sizeof(pkt))
		ksft_exit_fail_msg("sendto: %s\n", strerror(errno));

	/* receive — may see our own outgoing packet first, skip it */
	while (1) {
		n = recv(sock, buf, sizeof(buf), 0);
		if (n < 0) {
			ksft_test_result_fail("recv timed out waiting for SPI=8 reply\n");
			ksft_exit_fail();
		}

		riph = (struct iphdr *)buf;
		if ((size_t)n < (size_t)(riph->ihl * 4) + sizeof(*resph) + sizeof(*reh))
			continue;

		resph = (struct esp_hdr *)(buf + riph->ihl * 4);
		if (ntohl(resph->spi) != ESP_PING_SPI_REPLY)
			continue;

		reh = (struct esp_echo_hdr *)(resph + 1);

		ksft_test_result(ntohl(resph->spi) == ESP_PING_SPI_REPLY,
				 "received SPI=8 reply\n");
		ksft_test_result(reh->sub_type == ESP_ECHO_RESPONSE,
				 "sub_type == ESP_ECHO_RESPONSE\n");
		ksft_test_result(ntohs(reh->id) == myid && ntohs(reh->seq) == 1,
				 "id and seq match\n");
		break;
	}

	close(sock);
	ksft_finished();
}
