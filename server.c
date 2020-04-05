#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
 
 
#include<openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
 
/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 55000
 
/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28
#define OPENSSL_KEY_SIZE (256/8)
#define OPENSSL_IV_SIZE  (128/8)
#define HMAC_SIZE (256/8)

#define OPENSSL_ERR() { ERR_print_errors_fp(stderr); result = -1; goto openssl_cleanup; }
 
int debug;
char *progname;
 
static unsigned char openssl_key[OPENSSL_KEY_SIZE] = {0};
static EVP_PKEY *openssl_pkey;
static unsigned char openssl_iv[OPENSSL_IV_SIZE] = {0};
 
 
ssize_t encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
  EVP_CIPHER_CTX *ctx;
 
  int len;
 
  int result;
 
  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    ERR_print_errors_fp(stderr);
    return -1;
  }
 
  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, openssl_key, openssl_iv)) {
    ERR_print_errors_fp(stderr);
    return -1;
  }
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
     OPENSSL_ERR();
  } 

  result = len;
 
  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    OPENSSL_ERR();
  }
  result += len;
 
  /* Clean up */
openssl_cleanup:
  EVP_CIPHER_CTX_free(ctx);
 
  return result;
}
 
ssize_t decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
 
  int len;
 
  int result;
 
  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    ERR_print_errors_fp(stderr);
    return -1;
  }
 
  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, openssl_key, openssl_iv)) {
    OPENSSL_ERR();
  }
 
  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    OPENSSL_ERR();
  }
  result = len;
 
  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    OPENSSL_ERR();
  }
  result += len;
 
  /* Clean up */
openssl_cleanup:
  EVP_CIPHER_CTX_free(ctx);
 
  return result;
}

int hmac_sign(unsigned char *msg, int msg_len, unsigned char *hmac) {
  int result = 0;

  EVP_MD_CTX* ctx = EVP_MD_CTX_create();
  if (ctx == NULL) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  const EVP_MD* md = EVP_get_digestbyname("SHA256");
  if (md == NULL) OPENSSL_ERR();

  if (EVP_DigestInit_ex(ctx, md, NULL) != 1) OPENSSL_ERR();
  if (EVP_DigestSignInit(ctx, NULL, md, NULL, openssl_pkey) != 1) OPENSSL_ERR();
  if (EVP_DigestSignUpdate(ctx, msg, msg_len) != 1) OPENSSL_ERR();

  size_t hmac_size = 0;
  if (EVP_DigestSignFinal(ctx, NULL, &hmac_size) != 1 || hmac_size == 0) OPENSSL_ERR();
  if (hmac_size != HMAC_SIZE) {
    fprintf(stderr, "Unexpected hmac size %zu (expected %d)\n", hmac_size, HMAC_SIZE);
    result = -1;
    goto openssl_cleanup;
  }

  if (EVP_DigestSignFinal(ctx, hmac, &hmac_size) != 1) OPENSSL_ERR();
  if (hmac_size != HMAC_SIZE) {
    fprintf(stderr, "EVP_DigestSignFinal failed: mismatched sizes (%zu vs %d)\n",
        hmac_size, HMAC_SIZE);
    result = -1;
    goto openssl_cleanup;
  }

openssl_cleanup:
  EVP_MD_CTX_destroy(ctx);

  return result;
}

/*
 * Compute the SHA256 HMAC digest of msg and compare it to hmac. Returns 0 if digest matches,
 * 1 if digest does not match, or -1 if an error ocurred.
 */
int hmac_verify(unsigned char *msg, int msg_len, unsigned char *hmac) {
  unsigned char computed_hmac[HMAC_SIZE];
  if (hmac_sign(msg, msg_len, computed_hmac) < 0) {
    return -1;
  }

  return !!memcmp(hmac, computed_hmac, HMAC_SIZE);
}

 
/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags)
{
 
    struct ifreq ifr;
    int fd, err;
 
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    {
        perror("Opening /dev/net/tun");
        return fd;
    }
 
    memset(&ifr, 0, sizeof(ifr));
 
    ifr.ifr_flags = flags;
 
    if (*dev)
    {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }
 
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
    {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }
 
    strcpy(dev, ifr.ifr_name);
 
    return fd;
}
 
/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n)
{
 
    int nread;
 
    if ((nread = read(fd, buf, n)) < 0)
    {
        perror("Reading data");
        exit(1);
    }
    return nread;
}
 
/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n)
{
 
    int nwrite;
 
    if ((nwrite = write(fd, buf, n)) < 0)
    {
        perror("Writing data");
        exit(1);
    }
    return nwrite;
}
 
/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n)
{
 
    int nread, left = n;
 
    while (left > 0)
    {
        if ((nread = cread(fd, buf, left)) == 0)
        {
            return 0;
        }
        else
        {
            left -= nread;
            buf += nread;
        }
    }
    return n;
}
 
/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...)
{
 
    va_list argp;
 
    if (debug)
    {
        va_start(argp, msg);
        vfprintf(stderr, msg, argp);
        va_end(argp);
    }
}
 
/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...)
{
 
    va_list argp;
 
    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);
}
 
/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
    fprintf(stderr, "%s -h\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
    fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
    fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
    fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
    fprintf(stderr, "-d: outputs debug information while running\n");
    fprintf(stderr, "-h: prints this help text\n");
    exit(1);
}
 
void tap_To_net(int tap_fd, int net_fd, const struct sockaddr_in *remote)
{
    /* data from tun/tap: just read it and write it to the network */
 
    unsigned long int tap2net = 0;
    unsigned char buffer[BUFSIZE];
    int nbytes, nwrite;
 
    bzero(buffer, BUFSIZE);
    nbytes = cread(tap_fd, buffer, BUFSIZE);
 
    tap2net++;
    do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nbytes);
 
    unsigned char packet[BUFSIZE];
    unsigned char *hmac = packet;
    unsigned char *cipher = packet + HMAC_SIZE;

  ssize_t cipher_len = encrypt(buffer, nbytes, cipher);
  if (cipher_len == -1) {
    do_debug("TAP2NET %lu: Failed to encrypt message, dropping packet\n", tap2net);
    return;
  } else {
    do_debug("TAP2NET %lu: Encrypted message is %zd bytes\n", tap2net, cipher_len);
  }
  if (hmac_sign(cipher, cipher_len, hmac) < 0) {
    do_debug("TAP2NET %lu: Failed to compute message HMAC, dropping packet\n", tap2net);
    return;
  }
    /* sending data to net interface (physical) */
    nwrite = sendto(net_fd, cipher, cipher_len, 0, (const struct sockaddr *)remote, sizeof(*remote));
 
    if (nwrite == -1)
    {
        perror("sendto() couldn't send the packets to the physical network interface");
        exit(1);
    }
 
    do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
}
 
void net_To_tap(int net_fd, int tap_fd)
{
    /* data from the network: read it, and write it to the tun/tap interface.   
       * We need to read the length first, and then the packet */
 
    unsigned long int net2tap = 0;
    unsigned char buffer[BUFSIZE];
    int nread, nwrite;
    struct sockaddr_in remote;
    socklen_t remotelen;
 
    /* Read length */
    bzero(buffer, BUFSIZE);
    nread = recvfrom(net_fd, (char *)buffer, BUFSIZE,0,NULL,NULL);
    if (nread == 0)
    {
        /* ctrl-c at the other end */
        perror("recvfrom()");
        exit(1);
    }
 
    net2tap++;
 
    do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);
    unsigned char *hmac = buffer;
    unsigned char *cipher = buffer + HMAC_SIZE;
    size_t  cipher_len = nread - HMAC_SIZE;

  if (hmac_verify(cipher, cipher_len, hmac) != 0) {
    do_debug("NET2TAP %lu: Failed to verify HMAC, dropping packet\n", net2tap);
    return;
  }
    unsigned char plain[BUFSIZE];
  ssize_t plain_len = decrypt(cipher, nread, plain);
  if (plain_len == -1) {
    do_debug("NET2TAP %lu: Failed to decrypt message, dropping packet\n", net2tap);
    return;
  } else {
    do_debug("NET2TAP %lu: Decypted message is %zd bytes\n", net2tap, plain_len);
  }
 
    /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */
    nwrite = cwrite(tap_fd, plain, plain_len);
    do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
}
 
void init_openssl() {
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
}
 
void read_key(const char *file) {
  int fd = open(file, O_RDONLY);
  if (fd == -1) {
    perror("Error opening key file");
    exit(1);
  }
 
  ssize_t nbytes = read(fd, openssl_key, OPENSSL_KEY_SIZE);
  if (nbytes == -1) {
    perror("Error reading key file");
    exit(1);
  } else if (nbytes < OPENSSL_KEY_SIZE) {
    fprintf(stderr, "Invalid key length %zd (expected %d)", nbytes, OPENSSL_KEY_SIZE);
    exit(1);
  }
 
  // Check that the key isn't too long
  char dummy;
  if (read(fd, &dummy, 1) > 0) {
    fprintf(stderr, "Key is too long (expected %d bytes)", OPENSSL_KEY_SIZE);
    exit(1);
  }
}
 
void read_iv(const char *file) {
  int fd = open(file, O_RDONLY);
  if (fd == -1) {
    perror("Error opening iv file");
    exit(1);
  }
 
  ssize_t nbytes = read(fd, openssl_iv, OPENSSL_IV_SIZE);
  if (nbytes == -1) {
    perror("Error reading iv file");
    exit(1);
  } else if (nbytes < OPENSSL_IV_SIZE) {
    fprintf(stderr, "Invalid iv length %zd (expected %d)", nbytes, OPENSSL_IV_SIZE);
    exit(1);
  }
 
  // Check that the iv isn't too long
  char dummy;
  if (read(fd, &dummy, 1) > 0) {
    fprintf(stderr, "Iv is too long (expected %d bytes)", OPENSSL_IV_SIZE);
    exit(1);
  }
}
 
 
 
int main(int argc, char *argv[])
{
 
    int tap_fd, option;
    int flags = IFF_TUN;
    char if_name[IFNAMSIZ] = "";
    int header_len = IP_HDR_LEN;
    int maxfd;
    uint16_t nread, nwrite, plength;
    //  uint16_t total_len, ethertype;
    char buffer[BUFSIZE];
    struct sockaddr_in local, remote;
    char remote_ip[16] = "";
    unsigned short int port = PORT;
    int sock_fd, net_fd, optval = 1;
    socklen_t remotelen;
    int cliserv = -1; /* must be specified on cmd line */
    unsigned long int tap2net = 0, net2tap = 0;
 
    progname = argv[0];
 
    /* Check command line options */
    while ((option = getopt(argc, argv, "i:sc:p:k:e:uahd")) > 0)
    {
        switch (option)
        {
        case 'd':
            debug = 1;
            break;
        case 'h':
            usage();
            break;
        case 'i':
            strncpy(if_name, optarg, IFNAMSIZ - 1);
            break;
        case 's':
            cliserv = SERVER;
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'u':
            flags = IFF_TUN;
            break;
        case 'a':
            flags = IFF_TAP;
            header_len = ETH_HDR_LEN;
            break;
        case 'k':
             read_key(optarg);
             break;
        case 'e':
             read_iv(optarg);
             break;
        default:
            my_err("Unknown option %c\n", option);
            usage();
        }
    }
 
    argv += optind;
    argc -= optind;
 
    if (argc > 0)
    {
        my_err("Too many options!\n");
        usage();
    }
 
    if (*if_name == '\0')
    {
        my_err("Must specify interface name!\n");
        usage();
    }
    else if (cliserv < 0)
    {
        my_err("Must specify client or server mode!\n");
        usage();
    }
    else if ((cliserv == CLIENT) && (*remote_ip == '\0'))
    {
        my_err("Must specify server address!\n");
        usage();
    }
     
    init_openssl();
 
    /* initialize tun/tap interface */
    if ((tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0)
    {
        my_err("Error connecting to tun/tap interface %s!\n", if_name);
        exit(1);
    }
 
    do_debug("Successfully connected to interface %s\n", if_name);
 
    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket()");
        exit(1);
    }
 
    if(cliserv == SERVER)
    {
        /* Server, wait for connections */
 
        /* avoid EADDRINUSE error on bind() */
        if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0)
        {
            perror("setsockopt()");
            exit(1);
        }
 
        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port = htons(port);
        if (bind(sock_fd, (struct sockaddr *)&local, sizeof(local)) < 0)
        {
            perror("bind() error with the socket");
            exit(1);
        }
 
        do_debug("Bound to port %d\n", port);
 
        /* wait for connection request */
        char buffer[BUFSIZE];
        remotelen = sizeof(remote);
        memset(&remote, 0, remotelen);
        if ((recvfrom(sock_fd, (char *)buffer, BUFSIZE, MSG_WAITALL, (struct sockaddr *)&remote, &remotelen)) < 0)
        {
            perror("Not receving at server side");
            exit(1);
        }
          
        net_fd=sock_fd;
        do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
    }
 
    /* use select() to handle two descriptors at once */
    maxfd = (tap_fd > net_fd) ? tap_fd : net_fd;
 
    while (1)
    {
        int ret;
        fd_set rd_set;
 
        FD_ZERO(&rd_set);
        FD_SET(tap_fd, &rd_set);
        FD_SET(net_fd, &rd_set);
 
        ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
 
        if (ret < 0 && errno == EINTR)
        {
            continue;
        }
 
        if (ret < 0)
        {
            perror("select()");
            exit(1);
        }
 
        if (FD_ISSET(tap_fd, &rd_set))
        {
            tap_To_net(tap_fd, net_fd, &remote);
        }
 
        if (FD_ISSET(net_fd, &rd_set))
        {
            net_To_tap(net_fd, tap_fd);
        }
 
    }
 
    return (0);
}
 
 




