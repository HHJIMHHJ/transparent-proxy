#include <sys/stat.h>
#include <sys/epoll.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/select.h>
#include <linux/netfilter_ipv4.h>
#include <sys/ioctl.h>
#include "tc-proxy.h"

#define LISTENQ 10
#define MAXLINE 4096

#define DNS_SERVER "192.168.72.2"

int Connect_Serv(struct sockaddr_in);
int tcp_listen(int);
int checkclient(in_addr_t);

static struct argument global_argument;
bool singleConnect::running = true;

void* tcProxy::test(argument* arg)
{
	struct sockaddr_in cli_addr;
	socklen_t sin_size = sizeof(struct sockaddr_in);
    int connfd,sockfd;
    int port;

    flag = true;
    global_argument = *arg;
    free(arg);
    /*if (argc!=3){
        printf("Usage: %s -p port\n", argv[0]);
        return nullptr;
    }

    optind = 1;

	while( (opt = getopt(argc, argv, "p:")) != EOF) {
			switch(opt) {
				case 'p':
					port = (short) atoi(optarg);
					break;
				default:
					printf("Usage: %s -p port\n", argv[0]);
                    return nullptr;
			}
     }*/

    sockfd=tcp_listen(global_argument.port);
    emit debug_msg(QString("listening on port: %1, sockfd: %2").arg(global_argument.port).arg(sockfd));
    listen_socket = sockfd;

    int nonblocked = 1;
    ioctl(sockfd, FIONBIO, (char*)&nonblocked);
    while(flag){
				connfd=accept(sockfd,(struct sockaddr *)&cli_addr, &sin_size);
				if(connfd<0) {
				    continue;
				}
                if (checkclient(cli_addr.sin_addr.s_addr) == 1){
                    nonblocked = 0;
                    ioctl(connfd, FIONBIO, (char*)&nonblocked);
                    emit debug_msg(QString("connection with client established, client ip: %1, port: %2, fd: %3")
                                   .arg(inet_ntoa(cli_addr.sin_addr)).arg(ntohs(cli_addr.sin_port)).arg(connfd));
                    emit start_single_connect(connfd);
                }
				else
					close(connfd);
    	}
    close(listen_socket);
    emit debug_msg(QString("transparent proxy terminated"));
    return nullptr;
}

void singleConnect::run(){
    int servfd;
	struct sockaddr_in servaddr;
	socklen_t servlen=sizeof(struct sockaddr_in);

	if ( (getsockopt(clifd,SOL_IP,SO_ORIGINAL_DST,&servaddr,&servlen)) != 0 ){
		close(clifd);
        emit debug_msg(QString("Could not recognize the client."));
        return;
	}

	/*DNS service*/
	if (ntohs(servaddr.sin_port) == 53){

        if( dns_trans(clifd) == -1){
            emit debug_msg(QString("DNS failed."));
            return;
        }

        return;
	}

	else {
		if (checkserver(servaddr.sin_addr.s_addr) == -1){
			close(clifd);
            return;
		}
		if ((servfd = Connect_Serv(servaddr)) == -1){
            return;
		}
	
        emit debug_msg(QString("connection with server established, server ip: %1, port: %2, fd: %3")
                       .arg(inet_ntoa(servaddr.sin_addr)).arg(ntohs(servaddr.sin_port)).arg(servfd));
        http_trans(clifd,servfd);
        close(servfd);
        close(clifd);
        return;
    }
}

int dns_trans(){
    struct sockaddr_in dns_addr;
    struct sockaddr_in client_addr;
    int len;
    socklen_t namelen = sizeof(sockaddr_in);
    dns_addr.sin_addr.s_addr = INADDR_ANY;
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(global_argument.port);
    char buf[MAXLINE];

    int dnsfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(bind(dnsfd, (struct sockaddr *)&dns_addr, namelen) < 0) return -1;
    int nonblocked = 1;
    ioctl(dnsfd, FIONBIO, (char*)&nonblocked);
    while(true){
        if ((len = recvfrom(dnsfd, buf, MAXLINE, 0, (struct sockaddr *)&dns_addr, &namelen)) == -1)continue;
        if (dns_addr.sin_addr.s_addr == inet_addr(global_argument.client_ip)){
            client_addr = dns_addr;
            dns_addr.sin_addr.s_addr = inet_addr(DNS_SERVER);
            dns_addr.sin_port = htons(53);
            if (sendto(dnsfd, buf, len, 0, (struct sockaddr *)&dns_addr, namelen) < 0) return -1;
        }
        else if (dns_addr.sin_addr.s_addr == inet_addr(DNS_SERVER)){
            if (sendto(dnsfd, buf, len, 0, (struct sockaddr *)&client_addr, namelen) < 0) return -1;
        }
    }
}

int singleConnect::dns_trans(int clifd)
{
    struct sockaddr_in servaddr;
    char cli_buf[MAXLINE];
    char dns_buf[MAXLINE];
    int cli_length, dns_length;
    socklen_t namelen;
    int maxfdp;
    fd_set rset;
    struct timeval tv;

    tv.tv_sec = 1;
    tv.tv_usec = 0;


    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(DNS_SERVER);
    servaddr.sin_port = htons(53);
    namelen = sizeof(servaddr);
    int dnsfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ::connect(dnsfd, (struct sockaddr *)&servaddr, namelen);
    maxfdp=(clifd>=dnsfd?clifd:dnsfd ) + 1;

    emit debug_msg(QString("resolving domain name."));
    while (running){

        FD_ZERO(&rset);
        FD_SET( clifd,&rset );
        FD_SET( dnsfd,&rset );

        if(select( maxfdp,&rset,nullptr,nullptr,&tv ) <= 0){
            //printf("server error.\n");
            continue;
        }
        if (FD_ISSET(clifd, &rset)){
            cli_length = read(clifd, cli_buf, MAXLINE);
            if (cli_length <= 0) return 0;
            dns_length = cli_length - 2;
            memcpy(dns_buf, cli_buf + 2, dns_length);
            //printf("received dns message from client\n");
            if (send(dnsfd, dns_buf, dns_length, 0) < 0) return -1;
        }
        if (FD_ISSET(dnsfd, &rset)){
            dns_length = read(dnsfd, dns_buf, MAXLINE);
            //printf("dns length:%d\n", dns_length);
            memcpy(cli_buf + 2, dns_buf, dns_length);
            char tmp[4];
            memcpy(tmp, &dns_length, 4);
            cli_buf[0] = tmp[1];
            cli_buf[1] = tmp[0];
            //printf("%d %d\n", cli_buf[0], cli_buf[1]);
            cli_length = dns_length + 2;
            if (send(clifd, cli_buf, cli_length, 0) < 0) return -1;
        }
    }
    close(clifd);
    close(dnsfd);
}


int tcp_listen(int port)
{
	struct sockaddr_in cl_addr,proxyserver_addr;
	socklen_t sin_size = sizeof(struct sockaddr_in);
	int sockfd, accept_sockfd, on = 1;

	
	memset(&proxyserver_addr, 0, sizeof(proxyserver_addr));							
	proxyserver_addr.sin_family = AF_INET;
	proxyserver_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	proxyserver_addr.sin_port = htons(port);

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd < 0) {
		printf("Socket failed...Abort...\n");
		return -1;
	}
	
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on));

	if (bind(sockfd, (struct sockaddr *) &proxyserver_addr, sizeof(proxyserver_addr)) < 0) {
		printf("Bind failed...Abort...\n");
		return -1;
	}
	if (listen(sockfd, LISTENQ) < 0) {
		printf("Listen failed...Abort...\n");
		return -1;
	}
	return sockfd;
}

int singleConnect::checkserver(unsigned int serv_addr) {
	struct hostent *hostinfo;
    unsigned int** allowedip_list;
    struct in_addr s;
    for (int i = 0; i < global_argument.website_num; i++){
        int j = 0;
        hostinfo = gethostbyname(global_argument.websites[i]);
        allowedip_list = (unsigned int** )hostinfo->h_addr_list;
        while (allowedip_list[j] != nullptr){
            s.s_addr = *allowedip_list[j];
            //printf("%s ",inet_ntoa(s));
            s.s_addr = serv_addr;
            //printf("%s\n",inet_ntoa(s));
            if (*(allowedip_list[j]) == serv_addr){
                emit debug_msg(QString("Server IP authentication passed !"));
                return 1;
            }
            j++;
        }
    }
    emit debug_msg(QString("Server IP authentication failed !"));
	return -1;
}

int tcProxy::checkclient(unsigned int cli_addr) {
	int allowedip;
    inet_aton(global_argument.client_ip,(struct in_addr *)&allowedip);
    struct in_addr in_cli_addr;
    in_cli_addr.s_addr = cli_addr;
	if (allowedip == cli_addr)	{
        emit debug_msg(QString("Client IP authentication passed ! "));
        return 1;
	}
	else{
        emit debug_msg(QString("Client IP authentication failed !"));
        emit debug_msg(QString("client IP: %1, allowed IP: %2").arg(inet_ntoa(in_cli_addr)).arg(global_argument.client_ip));
		return -1;
	}
}


int Connect_Serv(struct sockaddr_in servaddr)
{
	int cnt_stat, remoteSocket;

	remoteSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (remoteSocket < 0) {
		printf("Cannot establish socket.\n");
		return -1;
	}
	servaddr.sin_family= AF_INET;
	cnt_stat = connect(remoteSocket, (struct sockaddr *) &servaddr, sizeof(servaddr));
	if (cnt_stat < 0) {
		printf("Remote connect failed.\n");
		return -1;
	}
	return remoteSocket;
}

int singleConnect::http_trans(int clifd, int servfd)
{
	int maxfdp, length;
	fd_set rset;
    struct timeval tv;
	char cli_buf[MAXLINE];
    char* serv_buf;
    char* serv_content;
    struct http_response_head *response_head_offsets = new http_response_head;
    char filename[50];
    FILE* f;
    char tmp[17];
    struct sockaddr_in servaddr;
    socklen_t servlen=sizeof(struct sockaddr_in);
    char request[100];
    char response_head[500];
    char* field;
    char* c1, *c2;

    getsockopt(clifd,SOL_IP,SO_ORIGINAL_DST,&servaddr,&servlen);

    sprintf(filename, "http_data/%d_%d_%s", clifd, servfd, inet_ntoa(servaddr.sin_addr));
    f = fopen(filename, "w");

    tv.tv_sec = 1;
    tv.tv_usec = 0;
	maxfdp=(clifd>=servfd?clifd:servfd ) + 1;
    while(running)
	{
		FD_ZERO(&rset);
		FD_SET( clifd,&rset );
		FD_SET( servfd,&rset );

        if(select( maxfdp,&rset,nullptr,nullptr,&tv ) <= 0){
            //printf("server error.\n");
			continue;
		}

		if( FD_ISSET(clifd,&rset))
		{
			int s;
			length = read(clifd,cli_buf,MAXLINE);
            if( length <= 0 ) break;
            printf("received a message from client socket %d, to server socket %d, length:%d.\n", clifd, servfd, length);
            c1 = strstr(cli_buf, "\r\n");
            if (c1 == nullptr) printf("not a http rquest head.\n");
            else{
                strncpy(request, cli_buf, c1 - cli_buf);
                request[c1 - cli_buf] = '\0';
                for (int i = 0; i < 9;i++){
                    if (global_argument.method_banned[i]){
                        switch (i){
                        case 0:if (strstr(request, "GET")){
                                fprintf(f, "GET method monitored!\n");
                                strcpy(cli_buf + 9, "HTTP/1.1 404 Not Found\r\n\r\n");
                                length = strlen(cli_buf);
                            i = 9;
                        }
                            break;
                        case 1:if (strstr(request, "HEAD")){
                                fprintf(f, "HEAD method monitored!\n");
                                i = 9;
                        }
                            break;
                        case 2:if (strstr(request, "POST")){
                            fprintf(f, "POST method monitored!\n");
                            i = 9;
                        }
                            break;
                        case 3:if (strstr(request, "PUT"));break;
                        case 4:if (strstr(request, "DELETE"));break;
                        case 5:if (strstr(request, "CONNECT"));break;
                        case 6:if (strstr(request, "OPTIONS"));break;
                        case 7:if (strstr(request, "TRACE"));break;
                        case 8:if (strstr(request, "PATCH"));
                        }
                    }
                }
                fprintf(f, "c-s\n%s\n\n", cli_buf);
            }
            if((s = send( servfd,cli_buf,length,0)) <= 0) {
				printf("send to server returns %d, error code %d.\n", s, errno);
                break;
			}
		}
		if( FD_ISSET(servfd,&rset) ){
            length = tcp_receive(servfd, serv_buf, serv_content, response_head_offsets);
            printf("received a message to client socket %d, from server socket %d, length:%d.\n", clifd, servfd, length);
            //printf("%s\n", serv_buf);
            if (length <= 0) break;
            if (serv_content == nullptr);
            else if(!response_head_offsets->content_len_offset);
            else{
                field = (char*)malloc(response_head_offsets->content_type_len + 1);
                strncpy(field, serv_buf + response_head_offsets->content_type_offset, response_head_offsets->content_type_len);
                field[response_head_offsets->content_type_len] = '\0';
                    for (int i = 0; i < 3;i++){
                        if (global_argument.file_type[i]){
                            switch (i){
                            case 0:if (strstr(field, "application/pdf")){
                                    fprintf(f, "pdf downloading monitored!\n");
                                    i = 3;
                                }
                                break;
                            case 2:if (strstr(field, "application/msword") || strstr(field, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")){
                                    fprintf(f, "msword downloading monitored!\n");
                                    if (global_argument.file_type[i] == 2){
                                        lseek(global_argument.fd[i], (off_t)0, SEEK_SET);
                                        printf("size of the file is: %d\n", global_argument.nSize[i]);
                                        length = global_argument.nSize[i]+ (serv_content - serv_buf);
                                        sprintf(tmp, "%d", global_argument.nSize[i]);
                                        serv_buf = (char*)realloc(serv_buf, global_argument.nSize[i] + (serv_content - serv_buf)
                                                                  - response_head_offsets->content_len_len + strlen(tmp));
                                        if ((c1 = serv_buf + response_head_offsets->content_len_offset + strlen(tmp))
                                                != (c2 = serv_buf + response_head_offsets->content_len_offset + response_head_offsets->content_len_len))
                                        {
                                            printf("1\n");
                                            memmove(c1, c2, serv_content - serv_buf - response_head_offsets->content_len_offset - response_head_offsets->content_len_len);
                                            serv_content = serv_content + strlen(tmp) - response_head_offsets->content_len_len;
                                            length += strlen(tmp) - response_head_offsets->content_len_len;
                                        }
                                        printf("2\n");
                                        memcpy(serv_buf + response_head_offsets->content_len_offset, tmp, strlen(tmp));
                                        printf("3\n");
                                        read(global_argument.fd[i], serv_content, global_argument.nSize[i]);
                                        printf("4\n");
                                    }
                                    i = 3;
                                }
                                break;
                            case 1:if (strstr(field, "application/vnd.ms-excel") || strstr(field, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")){
                                    fprintf(f, "msexcel downloading monitored!\n");
                                    i = 3;
                                }
                                break;
                            }
                        }
                    }
                    free(field);
                }
                fprintf(f, "s-c\n%s", response_head);
                if(send(clifd,serv_buf,length,0) <= 0) {
                    printf("send error. \n");
                    break;
                }
                printf("5\n");
                free(serv_buf);
            }
         }
    free(response_head_offsets);
    fclose(f);
}

//len = 0:connection terminated;len = -1:error
int singleConnect::tcp_receive(int fd, char* &buf, char* &content, struct http_response_head* head_offsets){
    int len, content_len, total_len = 0;
    char* head, *field, *c1, *c2;
    char* tmp_buf;
    tmp_buf = (char*)malloc(MAXLINE);
    len = read(fd, tmp_buf, MAXLINE);
    //printf("inside tcp_receive %d\n", len);
    total_len += len;
    if (len <= 0) return len;
    if (strncmp(tmp_buf, "HTTP", 4) != 0) {
        printf("not a http response head\n");
        buf = tmp_buf;
        content = nullptr;
        return len;
    }
    else{
        c1 = strstr(tmp_buf, "\r\n\r\n");
        head_offsets->head_len = c1 - tmp_buf + 4;
        if (head_offsets->head_len == len) {
            printf("content is empty.\n");
            buf = tmp_buf;
            content = nullptr;
            return len;
        }
        content = c1 + 4;
        head = (char*)malloc(head_offsets->head_len + 1);//include the dividing "\r\n\r\n", in case "Content-Length" is the last field
        strncpy(head, tmp_buf, head_offsets->head_len);
        head[head_offsets->head_len] = '\0';
        if(!strstr(head, "Content-Length: ") || !strstr(head, "Content-Type: ")) {
            printf("unable to recognize content length or content type\n");
            buf = tmp_buf;
            content = buf + head_offsets->head_len;
            head_offsets->content_len_offset = 0;
            return len;
        }
        c2 = strstr(head, "Content-Length: ");
        c1 = strstr(c2, "\r\n");
        head_offsets->content_len_offset = c2 + 16 - head;
        head_offsets->content_len_len = c1 - c2 - 16;
        field = (char*)malloc(head_offsets->content_len_len + 1);
        strncpy(field, c2 + 16, head_offsets->content_len_len);
        field[head_offsets->content_len_len] = '\0';
        content_len = atoi(field);
        c1 = strstr(head, "Content-Type: ");
        c2 = strstr(c1, "\r\n");
        head_offsets->content_type_offset = c1 - head;
        head_offsets->content_type_len = c2 - c1;
        free(field);
        free(head);
        if (content_len == 0) {
            printf("malformed packet\n");
            return -1;
        }
        content_len -= tmp_buf + len - content;
        buf = (char*)malloc(total_len + content_len + 1);
        memcpy(buf, tmp_buf, total_len);
        content = buf + (content - tmp_buf);
        while(content_len > 0){
            len = read(fd, tmp_buf, MAXLINE);
            content_len -= len;
            memcpy(buf + total_len, tmp_buf, len);
            total_len += len;
        }
        buf[total_len] = '\0';
        return total_len;
    }
}
