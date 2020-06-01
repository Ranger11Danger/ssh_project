#define LIBSSH_STATIC 1
#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int verify_knownhost(ssh_session session)
{
    enum ssh_known_hosts_e state;
    unsigned char *hash = NULL;
    ssh_key srv_pubkey = NULL;
    size_t hlen;
    char buf[10];
    char *hexa;
    char *p;
    int cmp;
    int rc;
 
    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        return -1;
    }
 
    rc = ssh_get_publickey_hash(srv_pubkey,
                                SSH_PUBLICKEY_HASH_SHA1,
                                &hash,
                                &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        return -1;
    }
 
    state = ssh_session_is_known_server(session);
    switch (state) {
        case SSH_KNOWN_HOSTS_OK:
            /* OK */
 
            break;
        case SSH_KNOWN_HOSTS_CHANGED:
            fprintf(stderr, "Host key for server changed: it is now:\n");
            ssh_print_hexa("Public key hash", hash, hlen);
            fprintf(stderr, "For security reasons, connection will be stopped\n");
            ssh_clean_pubkey_hash(&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_OTHER:
            fprintf(stderr, "The host key for this server was not found but an other"
                    "type of key exists.\n");
            fprintf(stderr, "An attacker might change the default server key to"
                    "confuse your client into thinking the key does not exist\n");
            ssh_clean_pubkey_hash(&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            fprintf(stderr, "Could not find known host file.\n");
            fprintf(stderr, "If you accept the host key here, the file will be"
                    "automatically created.\n");
 
            /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */
 
        case SSH_KNOWN_HOSTS_UNKNOWN:
            hexa = ssh_get_hexa(hash, hlen);
            fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
            fprintf(stderr, "Public key hash: %s\n", hexa);
            ssh_string_free_char(hexa);
            ssh_clean_pubkey_hash(&hash);
            p = fgets(buf, sizeof(buf), stdin);
            if (p == NULL) {
                return -1;
            }
 
            cmp = strncasecmp(buf, "yes", 3);
            if (cmp != 0) {
                return -1;
            }
 
            rc = ssh_session_update_known_hosts(session);
            if (rc < 0) {
                fprintf(stderr, "Error %s\n", strerror(errno));
                return -1;
            }
 
            break;
        case SSH_KNOWN_HOSTS_ERROR:
            fprintf(stderr, "Error %s", ssh_get_error(session));
            ssh_clean_pubkey_hash(&hash);
            return -1;
    }
 
    ssh_clean_pubkey_hash(&hash);
    return 0;
}

int interactive_shell_session(ssh_session session, ssh_channel channel)
{
  int rc;
  rc = ssh_channel_request_pty(channel);
  if (rc != SSH_OK) return rc;
 
  rc = ssh_channel_change_pty_size(channel, 80, 24);
  if (rc != SSH_OK) return rc;
 
  rc = ssh_channel_request_shell(channel);
  if (rc != SSH_OK) return rc;
  
  char buffer[256];
  int nbytes, nwritten;
  while (ssh_channel_is_open(channel) &&
         !ssh_channel_is_eof(channel))
  {
        struct timeval timeout;
    ssh_channel in_channels[2], out_channels[2];
    fd_set fds;
    int maxfd;
 
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    in_channels[0] = channel;
    in_channels[1] = NULL;
    FD_ZERO(&fds);
    FD_SET(0, &fds);
    FD_SET(ssh_get_fd(session), &fds);
    maxfd = ssh_get_fd(session) + 1;
 
    ssh_select(in_channels, out_channels, maxfd, &fds, &timeout);
 
    if (out_channels[0] != NULL)
    {
      nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
      if (nbytes < 0) return SSH_ERROR;
      if (nbytes > 0)
      {
        nwritten = write(1, buffer, nbytes);
        if (nwritten != nbytes) return SSH_ERROR;
      }
    }
 
    if (FD_ISSET(0, &fds))
    {
      nbytes = read(0, buffer, sizeof(buffer));
      if (nbytes < 0) return SSH_ERROR;
      if (nbytes > 0)
      {
        nwritten = ssh_channel_write(channel, buffer, nbytes);
        if (nbytes != nwritten) return SSH_ERROR;
      }
    }
  }
 
  return rc;
}


int get_channel(ssh_session session)
{
    ssh_channel channel;
  int rc;
 
  channel = ssh_channel_new(session);
  if (channel == NULL)
    return SSH_ERROR;
 
  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK)
  {
    ssh_channel_free(channel);
    return rc;
  }
 
  interactive_shell_session(session, channel);
 
  ssh_channel_close(channel);
  ssh_channel_send_eof(channel);
  ssh_channel_free(channel);
 
  return SSH_OK;
}


int main()
{
  ssh_session my_ssh_session;
  int rc;
  char *password;
  // Open session and set options
  my_ssh_session = ssh_new();
  if (my_ssh_session == NULL)
    exit(-1);
  ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "localhost");
  ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, "josh");
 
  // Connect to server
  rc = ssh_connect(my_ssh_session);
  if (rc != SSH_OK)
  {
    fprintf(stderr, "Error connecting to localhost: %s\n",
            ssh_get_error(my_ssh_session));
    ssh_free(my_ssh_session);
    exit(-1);
  }
 
  // Verify the server's identity
  if (verify_knownhost(my_ssh_session) < 0)
  {
    ssh_disconnect(my_ssh_session);
    exit(-1);
  }
 
  // Authenticate ourselves
  password = getpass("Password: ");
  rc = ssh_userauth_password(my_ssh_session, NULL, password);
  if (rc != SSH_AUTH_SUCCESS)
  {
    fprintf(stderr, "Error authenticating with password: %s\n",
            ssh_get_error(my_ssh_session));
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    exit(-1);
  }
 
  get_channel(my_ssh_session);



  ssh_disconnect(my_ssh_session);
  ssh_free(my_ssh_session);
}
