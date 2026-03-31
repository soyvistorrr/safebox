/*
 * safebox_client.c
 *
 * CI3825 - Sistemas de Operacion I
 * Proyecto 3 - SafeBox
 *
 * ╔══════════════════════════════════════════════════════╗
 * ║  ARCHIVO A IMPLEMENTAR POR LOS ESTUDIANTES           ║
 * ║  Este es el codigo de REFERENCIA del profesor.       ║
 * ║  Los estudiantes entregaran su propia version.       ║
 * ╚══════════════════════════════════════════════════════╝
 *
 * Implementa las funciones declaradas en safebox_client.h.
 * Este archivo es la "biblioteca de enlace" entre el
 * minishell (safebox-shell.c) y el daemon.
 *
 * Syscalls principales usadas:
 *   socket(2), connect(2), send(2), recv(2)
 *   sendmsg(2), recvmsg(2) con SCM_RIGHTS
 *   open(2), read(2), fstat(2)
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>

#include "safebox.h"
#include "safebox_client.h"

int sb_connect(const char *socket_path, const char *password)
{
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0)
        return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1)
    {
        close(sockfd);
        return -1;
    }

    sb_auth_msg_t auth_msg;
    auth_msg.op = 0;
    auth_msg.password_hash = sb_djb2(password);

    if (send(sockfd, &auth_msg, sizeof(auth_msg), 0) != sizeof(auth_msg))
    {
        close(sockfd);
        return -1;
    }

    uint8_t status;
    if (recv(sockfd, &status, sizeof(uint8_t), MSG_WAITALL) != sizeof(uint8_t) || status != SB_OK)
        return -1;

    return sockfd;
}

int sb_list(int sockfd, char *buf, size_t buflen)
{
    if (sockfd < 0 || buf == NULL || buflen == 0)
        return -1;

    uint8_t op = SB_OP_LIST;
    if (send(sockfd, &op, sizeof(uint8_t), 0) != sizeof(uint8_t))
        return -1;

    uint8_t status;
    if (recv(sockfd, &status, sizeof(uint8_t), MSG_WAITALL) != sizeof(uint8_t) || status != SB_OK)
        return -1;

    uint32_t list_size = 0;
    if (recv(sockfd, &list_size, sizeof(uint32_t), MSG_WAITALL) != sizeof(uint32_t))
        return -1;

    uint32_t bytes_to_read = list_size;
    if (bytes_to_read >= buflen)
    {
        bytes_to_read = buflen - 1;
    }

    if (bytes_to_read > 0)
    {
        if (recv(sockfd, buf, bytes_to_read, MSG_WAITALL) != bytes_to_read)
            return -1;
    }

    buf[bytes_to_read] = '\0';

    return 0;
}

int sb_del(int sockfd, const char *filename)
{
    if (sockfd < 0 || filename == NULL)
    {
        return -1;
    }

    uint8_t op = SB_OP_DEL;
    if (send(sockfd, &op, sizeof(uint8_t), 0) != sizeof(uint8_t))
        return -1;

    size_t name_len = strlen(filename) + 1;

    if (send(sockfd, filename, name_len, 0) != (ssize_t)name_len)
        return -1;

    uint8_t status;
    if (recv(sockfd, &status, sizeof(uint8_t), MSG_WAITALL) != sizeof(uint8_t) || status != SB_OK)
        return -1;

    return 0;
}

int sb_put(int sockfd, const char *filename, const char *filepath)
{
    if (sockfd < 0 || filename == NULL || filepath == NULL)
        return -1;

    int fd_local = open(filepath, O_RDONLY);
    if (fd_local < 0)
        return -1;

    struct stat st;
    if (fstat(fd_local, &st) < 0)
    {
        close(fd_local);
        return -1;
    }
    uint32_t file_size = (uint32_t)st.st_size;

    uint8_t op = SB_OP_PUT;
    if (send(sockfd, &op, sizeof(uint8_t), 0) != sizeof(uint8_t))
    {
        close(fd_local);
        return -1;
    }

    size_t name_len = strlen(filename) + 1;
    if (send(sockfd, filename, name_len, 0) != (ssize_t)name_len)
    {
        close(fd_local);
        return -1;
    }

    if (send(sockfd, &file_size, sizeof(uint32_t), 0) != sizeof(uint32_t))
    {
        close(fd_local);
        return -1;
    }

    char buffer[4096];
    ssize_t bytes_read;
    while ((bytes_read = read(fd_local, buffer, sizeof(buffer))) > 0)
    {
        if (send(sockfd, buffer, bytes_read, 0) != bytes_read)
        {
            close(fd_local);
            return -1;
        }
    }
    close(fd_local);

    uint8_t status;
    if (recv(sockfd, &status, sizeof(uint8_t), MSG_WAITALL) != sizeof(uint8_t))
    {
        return -1;
    }

    return (status == SB_OK) ? 0 : -1;
}

void sb_bye(int sockfd)
{
    uint8_t op = SB_OP_BYE;
    send(sockfd, &op, sizeof(uint8_t), 0);
    close(sockfd);
}

int sb_get(int sockfd, const char *filename)
{
    if (sockfd < 0 || filename == NULL)
        return -1;

    uint8_t op = SB_OP_GET;
    if (send(sockfd, &op, sizeof(uint8_t), 0) != sizeof(uint8_t))
        return -1;

    size_t name_len = strlen(filename) + 1;
    if (send(sockfd, filename, name_len, 0) != (ssize_t)name_len)
        return -1;

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));

    struct iovec iov[1];
    uint8_t status;
    iov[0].iov_base = &status;
    iov[0].iov_len = sizeof(status);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    union
    {
        struct cmsghdr align;
        char buf[CMSG_SPACE(sizeof(int))];
    } cmsg_buf;
    memset(&cmsg_buf, 0, sizeof(cmsg_buf));
    msg.msg_control = cmsg_buf.buf;
    msg.msg_controllen = sizeof(cmsg_buf.buf);

    if (recvmsg(sockfd, &msg, MSG_WAITALL) <= 0)
        return -1;
    if (status != SB_OK)
        return -1;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg != NULL && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
    {
        int received_fd;
        memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(int));
        return received_fd;
    }

    return -1;
}