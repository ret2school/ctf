#include <stdio.h>
typedef unsigned short _WORD;

int main(void) {
    char v11[82];
    v11[81] = 0;
    memcpy(v11, "                                                                                6", sizeof(v11));
    v11[10] = 50;
    *(_WORD *)&v11[20] = 0x3933;
    v11[29] = 53;
    v11[36] = 55;
    *(_WORD *)&v11[55] = 13877;
    v11[64] = 49;
    memcpy(&v11[3], "546", 3);
    *(_WORD *)&v11[49] = 13113;
    v11[59] = 56;
    *(_WORD *)&v11[67] = 14643;
    v11[8] = 57;
    v11[17] = 55;
    *(_WORD *)&v11[26] = 14644;
    v11[34] = 55;
    v11[43] = 50;
    v11[78] = 56;
    printf("%s", v11);
}