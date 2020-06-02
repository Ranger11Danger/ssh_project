#define LIBSSH_STATIC 1
#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pthread.h> 
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

char **PORT;
char **USER;
char **HOST;
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

char run_remote_command(ssh_session session, char *command)
{
    ssh_channel channel;
    int rc;
    char buffer[256];
    int nbytes;
  
    channel = ssh_channel_new(session);
    if (channel == NULL)
        return SSH_ERROR;
  
    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
        ssh_channel_free(channel);
        return rc;
    }
  
    rc = ssh_channel_request_exec(channel, command);
    if (rc != SSH_OK)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }
    //FILE *fptr;
    //fptr = fopen("/tmp/test.txt","w");
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    while (nbytes > 0)
    {
        //char output[nbytes];
        //strcpy(output, buffer);
        //printf("%s", output);
        //if (write(fileno(fptr), buffer, nbytes) != (unsigned int) nbytes)
        if (write(1, buffer, nbytes) != (unsigned int) nbytes)
        {
            //fclose(fptr);
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return SSH_ERROR;
        }
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    }
  
    if (nbytes < 0)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return SSH_ERROR;
    }
  
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
  
    return SSH_OK;
}

int myThread(ssh_session session) 
{ 
    sleep(1); 
    run_remote_command(session, "id");
    return NULL;
}

ssh_session create_connection()
{
    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    ssh_init();
    ssh_session my_ssh_session;
    int rc;
    char *password;
    // Open session and set options
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
        exit(-1);

    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, HOST);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, USER);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT_STR, PORT);
  
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
    
    // this is where our command is executed can be called multiple times
    //pthread_t thread_id;
    //pthread_create(&thread_id, NULL, &myThread, my_ssh_session);
    //pthread_join(thread_id, NULL);
    
    
    return my_ssh_session;
    //ssh_disconnect(my_ssh_session);
    //ssh_free(my_ssh_session);
}

int main(int argc, char **argv){

    if (argc < 7){
        printf("Usage:\n-port = port to connect to\n-user = username to login with\n-host = server to connect to\n");
        return NULL;
    }

    for(int i = 1; i < argc; i++){
        if (strcmp(argv[i], "-port") == 0){
            PORT = argv[i + 1];
        }
        else if (strcmp(argv[i], "-user") == 0){
            USER = argv[i + 1];
        }
        else if (strcmp(argv[i], "-host") == 0){
            HOST = argv[i + 1];
        }
        
    }
    
    ssh_session test_session;
    test_session = create_connection();
    //pthread_t thread_id;
    //pthread_create(&thread_id, NULL, &myThread, test_session);
    //pthread_join(thread_id, NULL);
    char command[256];
    while(1)
    {
        printf("#");
        fgets(command, sizeof command, stdin);
        run_remote_command(test_session, command);
    }
    
    
    
    
}
