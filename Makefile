LIBS = "-Iinclude/

antivirus: main.c
	$(CC) $? -o $@

clean:
	@rm -f antivirus

