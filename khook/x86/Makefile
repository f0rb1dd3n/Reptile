STUB = stub.S

stub: FORCE
	gcc $(CFLAGS) -nostdlib -Wl,-e0 $(STUB) -o stub
	objcopy --dump-section .text=/dev/stdout stub | xxd -i - >stub.inc
	gcc $(CFLAGS) -m32 -nostdlib -Wl,-e0 $(STUB) -o stub32
	objcopy --dump-section .text=/dev/stdout stub32 | xxd -i - >stub32.inc

clean:
	rm -f stub *.inc

FORCE:
