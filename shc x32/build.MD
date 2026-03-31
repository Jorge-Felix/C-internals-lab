# Step 1 ->

gcc -m64 -c -Os \
    -fno-stack-protector \
    -fno-exceptions \
    -fno-asynchronous-unwind-tables \
    -fno-unwind-tables \
    -fno-pic \
    -fno-jump-tables \
    -fno-ident \
    -fcf-protection=none \
    x64/shc.c -o x64/shc.o

# Step 2 ->
objcopy -O binary -j .text x64/shc.o x64/shellcode.bin

# Step 3 (optional) ->
python bin2c.py x64/shellcode.bin
