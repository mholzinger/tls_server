#ifndef TLS_SERVER_H_
#define TLS_SERVER_H_

#include <string.h>
#include <stdbool.h>

/* Sockets */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

/* SSL */
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

enum { error_buf = 1024, msg_buf = 2048 };
enum { closed_socket = -1, socket_error = -1 };

int close_socket(int socket);
void load_certs(void);
void set_fips(void);
void print_ssl_error_stack(void);
int tcp_init(void);
SSL* tls_accept(int server_socket, int client_socket);
void tls_init(void);
void tls_cleanup(SSL* pSsl);
void v_print(const char* output, ...);
void verify_certs(SSL* pSsl);

#endif /* TLS_SERVER_H_ */
