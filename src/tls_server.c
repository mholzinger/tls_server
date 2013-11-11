#include "tls_server.h"

SSL_CTX* global_ssl_ctx;
int gi_fips_mode;

/* set to print prog output to stdout */
int verbose_flag = 1;

int main(int argc, char** argv)
{
    int server_socket = closed_socket;
    int client_socket = 0;
    int irc = 0;

    SSL* stack_ssl_ctx = NULL;

    /* Set FIPS mode */
    set_fips(); if (gi_fips_mode != 1) goto Error;

    /* Bind to TCP address using sockets  */
    server_socket = tcp_init();
    if (server_socket == socket_error) goto Error;

    /* Build SSL/TLS context structure */
    tls_init();
    if (global_ssl_ctx == NULL) goto Error;

    /* Load x509 certificates into struct */
    load_certs();
    if (global_ssl_ctx == NULL) goto Error;

    while (true)
    {
        stack_ssl_ctx = tls_accept(server_socket, client_socket);
        if (!stack_ssl_ctx)
        {
            client_socket = close_socket(client_socket);
            continue;
        }

        verify_certs(stack_ssl_ctx);

        v_print("info: close client socket connection");
        client_socket = close_socket(client_socket);

    } /* end while */

    Error:
    client_socket = close_socket(client_socket);
    server_socket = close_socket(server_socket);
    tls_cleanup(stack_ssl_ctx);
    v_print("exit status :<error>");
    return irc;
}
/*----------------------------------------------------------------------------*/

int close_socket(int socket)
{
    if (socket != closed_socket)
    {
        v_print("info : closing socket <%d>", socket);
        /* close socket */
        if (close(socket))
        {
            v_print("error <18>: close for socket failed");
        }
        socket = closed_socket; /* Since 0 is a valid value */
    }
    return socket;
}
/*----------------------------------------------------------------------------*/

void load_certs(void)
{
    char* certs_directory = NULL;
    char* cert = NULL;
    char* key = NULL;
    char* ca_cert = NULL;

    int irc = 0;

    int iMode = 0;
    int iVerifyDepth = 0;

    /* certificate values */
    certs_directory = "./crt";
    ca_cert = "./crt/ca_cert.pem";
    cert = "./crt/server_cert.pem";
    key = "./crt/server_key.pem";

    /* Load server signed cert into CTX */
    v_print("info: Loading server cert into CTX struct");
    irc = SSL_CTX_use_certificate_file(global_ssl_ctx, (const char*)cert,
        SSL_FILETYPE_PEM);
    if (irc != 1)
    {
        v_print("error <8>: SSL_CTX_use_certificate_file() failed for <%s>",
            (char*)cert);
        print_ssl_error_stack();
        goto Error;
    }

    /* Ignoring SSL_CTX_set_default_passwd_cb() private key
       not password protected */

    /* Load server private key into the context */
    v_print("info: Loading server private key into CTX struct");
    irc = SSL_CTX_use_PrivateKey_file(global_ssl_ctx, (const char*)key,
        SSL_FILETYPE_PEM);
    if (irc != 1)
    {
        v_print("error <9>: SSL_CTX_use_PrivateKey_file() failed for key <%s>",
            key);
        print_ssl_error_stack();
        goto Error;
    }

    /* Check if the server cert and the private-key match */
    v_print("info: Checking server cert matches private key");
    irc = SSL_CTX_check_private_key((const SSL_CTX*)global_ssl_ctx);
    if (irc != 1)
    {
        v_print("Error <10>: SSL_CTX_check_private_key() failed for "
            "SSL_CTX* (private key does not match certificate)");
        print_ssl_error_stack();
        goto Error;
    }

    /* Load trusted CA for client certificate into context */
    v_print("info: Loading CA cert into CTX struct");
    irc = SSL_CTX_load_verify_locations(global_ssl_ctx, (const char*)ca_cert,
        (const char*)certs_directory);
    if (irc != 1)
    {
        v_print("error <11>: SSL_CTX_load_verify_locations() failed for ca cert "
            "<%s> in dir <%s>", ca_cert, certs_directory);
        goto Error;
    }

    v_print("info: Set mode to require client peer certificate");
    /* Set flag to require client cert verification */
    iMode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    iVerifyDepth = 1;

    SSL_CTX_set_verify(global_ssl_ctx, iMode, NULL);
    SSL_CTX_set_verify_depth(global_ssl_ctx, iVerifyDepth);

    /* No errors - everyone is happy! */
    return;

    Error:
    global_ssl_ctx = NULL;
    return;
}

/*----------------------------------------------------------------------------*/
void print_ssl_error_stack(void)
{
    /* loop to clear the openssl error stack on non-zero ERR_get_error */
    char error_msg[error_buf];
    unsigned long ul_error = ERR_get_error();

    while (ul_error != 0)
    {
        ERR_error_string_n(ul_error, error_msg, (size_t)error_buf);
        (void)v_print("<%s>", error_msg);
        ul_error = ERR_get_error();
    }

    /* tidy */
    (void)memset((void*)error_msg, 0, sizeof(error_msg));
    ul_error = 0;
}

/*----------------------------------------------------------------------------*/
void set_fips(void)
{
    if (!FIPS_mode_set(1))
    {
        v_print("error <1>: FIPS mode has not been set");
        print_ssl_error_stack();
    }
    else (void)v_print("FIPS mode has been set");

    gi_fips_mode = FIPS_mode();
}

/*----------------------------------------------------------------------------*/
SSL* tls_accept(int server_socket, int client_socket)
{
    int irc = 0;
    BIO* pSbio = NULL;
    SSL* stack_ssl_ctx = NULL;
//    int client_socket = 0;

    struct sockaddr_in stClientSockAddr;
    unsigned int uiClientLen;

    /* Server accept on socket */
    client_socket = accept(server_socket,
           (struct sockaddr*)&stClientSockAddr, &uiClientLen);
    if (client_socket == socket_error)
    {
    /* Accept failed */
    v_print("error <12>: TCP accept() failed for socket, <%d>", server_socket);
        goto Error;
    }

    v_print("info: server accept on socket <%d>", client_socket);

    /* Connect it to the SSL socket */
    pSbio = BIO_new_socket(client_socket, BIO_NOCLOSE);
    if (pSbio == NULL)
    {
        v_print("error <13>: BIO_new_socket() failed to connect socket <%d>",
            (int)client_socket);
        print_ssl_error_stack();
        goto Error;
    }

    /* Create SSL struct for this connection */
    stack_ssl_ctx = SSL_new(global_ssl_ctx);
    if (stack_ssl_ctx == NULL)
    {
        v_print("error <14>: SSL_new() failed to allocate new SSL structure");
        goto Error;
    }

    /* Connect the SSL object with a BIO */
    SSL_set_bio(stack_ssl_ctx, pSbio, pSbio);

    /* SSL_accept */
    irc = SSL_accept(stack_ssl_ctx);
    if (irc != 1)
    {
        v_print("error <15>: SSL_accept() error, accept failed");
        print_ssl_error_stack();
        goto Error;
    }
    return stack_ssl_ctx;

    Error:
    tls_cleanup(stack_ssl_ctx);
    stack_ssl_ctx = NULL;
    return stack_ssl_ctx;
}

/*----------------------------------------------------------------------------*/
int tcp_init(void)
{
    int irc = 0;
    int server_socket;

    char* port = NULL;
    struct sockaddr_in stSvrSockAddr;
    uint16_t ut16Port;

    /* Init socket */
    v_print("info: TCP initialize socket");

    port = "9000";
    server_socket = closed_socket;

    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket < 0)
    {
        v_print("error <2>: Failed to initialize new socket");
        goto Error;
    }

    /* Setup socket */
    (void)memset((void*)&stSvrSockAddr, 0, sizeof(stSvrSockAddr));
    stSvrSockAddr.sin_family = (sa_family_t)AF_INET;
    stSvrSockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    ut16Port = (uint16_t)atol((const char*)port);
    stSvrSockAddr.sin_port = htons(ut16Port);

    /* Bind to port */
    v_print("info: Bind socket to address/port:<%s><%s>", "localhost",
        port);

    irc = bind(server_socket, (const struct sockaddr*)&stSvrSockAddr,
        (socklen_t)sizeof(stSvrSockAddr));
    if (irc != 0)
    {
        v_print("error <3>: TCP bind() failed for port <%s>", port);
        goto Error;
    }

    v_print("info: TCP setup listen");

    irc = listen(server_socket, 5);
    if (irc != 0)
    {
        v_print("error <4>: TCP listen() failed for socket <%d>", server_socket);
        goto Error;
    }

    /* Our server is running! let's return that socket! */
    return server_socket;

    Error:
    server_socket = socket_error;
    return server_socket;
}

/*----------------------------------------------------------------------------*/
void tls_init(void)
{
    char* session_cipher = "AES128-SHA:AES256-SHA";
    int irc = 0;

    const SSL_METHOD* SSL_method_pointer;

    v_print("info: ssl server started by User ID <%d>", (int)getuid());

    /* Initialize SSL error strings */
    (void)SSL_library_init();
    SSL_load_error_strings();

    v_print("info: setting TLS method to 1.1");
    SSL_method_pointer = TLSv1_1_method();
//    SSL_method_pointer = TLSv1_1_server_method();
    if (SSL_method_pointer == NULL)
    {
        v_print("error <5>: TLSv1_method() failed to allocate pointer");
        goto Error;
    }

    v_print("info: calling for new SSL_CTX method pointer");
    global_ssl_ctx = SSL_CTX_new(SSL_method_pointer);
    if (global_ssl_ctx == NULL)
    {
        v_print("error <6>: SSL_CTX_new() failed to allocate pointer");
        goto Error;
    }

    /* Create context */
    v_print("info: disabling session caching");
    (void)SSL_CTX_set_session_cache_mode(global_ssl_ctx, (long)SSL_SESS_CACHE_OFF);


    v_print("info: restricting cipher list to <%s>", session_cipher);
    irc = SSL_CTX_set_cipher_list(global_ssl_ctx, session_cipher);
    if (!irc)
    {
        v_print("error <7>: SSL_CTX_set_cipher_list failed");
        print_ssl_error_stack();
        goto Error;
    }

    /* No errors - everyone is happy! */
    return;

    Error:
    global_ssl_ctx = NULL;
    return;
}

/*----------------------------------------------------------------------------*/
void tls_cleanup(SSL* stack_ssl_ctx)
{
    if (stack_ssl_ctx)
    {
        if (SSL_shutdown(stack_ssl_ctx) == -1)
        {
            v_print("error <21>: SSL_Shutdown error");
            print_ssl_error_stack();
        }
        v_print("info : SSL_free()");
        SSL_free(stack_ssl_ctx);
        stack_ssl_ctx = NULL;
    }

    ERR_remove_state(0);
    ERR_free_strings();
}

/*----------------------------------------------------------------------------*/
void v_print(const char* output, ...)
{
    /* if verbose_flag not set, bail */
    if (verbose_flag == 0) return;

    char msg_string[msg_buf];
    int array_count;

    va_list args;
    va_start(args, output);
    vsprintf(msg_string, output, args);
    va_end(args);

    /* Append newline char; NULL terminate */
    array_count = (int)strlen(msg_string);
    msg_string[array_count++] = 0x0a;
    msg_string[array_count] = 0x00;

    (void)printf("%s", msg_string);
}

/*----------------------------------------------------------------------------*/
void verify_certs(SSL* stack_ssl_ctx)
{
    X509* pX509ClientCert = NULL;
    long lRc = 0;

    v_print("info: get peer certificate");
    pX509ClientCert = SSL_get_peer_certificate((const SSL*)stack_ssl_ctx);
    if (pX509ClientCert == NULL)
    {
        v_print("error <16>: SSL_get_peer_certificate() failed (returned NULL)");
        print_ssl_error_stack();
        goto Error;
    }

    /* SSL_get_verify_result */
    v_print("info: verify certificate results");
    lRc = SSL_get_verify_result((const SSL*)stack_ssl_ctx);
    if (lRc != X509_V_OK)
    {
        v_print("error <17>: SSL_get_verify_result failed to return "
        "value of 'X509_V_OK'");
        goto Error;
    }

    /* Verify complete */
    v_print("info: verify complete, free connection");
    X509_free(pX509ClientCert);

    /* end while loop */
    return;

    Error:
    pX509ClientCert = NULL;
    stack_ssl_ctx = NULL;
    return;
}

