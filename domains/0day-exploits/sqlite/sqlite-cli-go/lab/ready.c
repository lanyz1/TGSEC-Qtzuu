#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#define READY_PORT 18920

int main(void) {
    int fd;
    int one = 1;
    struct sockaddr_in addr = {0};

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return 1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
        return 1;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(READY_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        return 1;
    }
    if (listen(fd, 8) != 0) {
        return 1;
    }
    for (;;) {
        int conn = accept(fd, 0, 0);
        if (conn >= 0) {
            close(conn);
        }
    }
}
