all:
	@gcc client.c -lssh -lpthread -o client

clean:
	@rm client
