#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int print_flag(char *buf)
{
  unsigned int i;

  printf("Hero{");
  for ( i = 8LL; i != 89; i += 9LL )
  {
    putchar(buf[i - 8]);
    putchar(buf[i - 7]);
    putchar(buf[i - 6]);
    putchar(buf[i - 5]);
    putchar(buf[i - 4]);
    putchar(buf[i - 3]);
    putchar(buf[i - 2]);
    putchar(buf[i - 1]);
    putchar(buf[i]);
  }
  return puts("}");
}

int checksudoku(char *inputbuf, unsigned int chr1, unsigned int chr2, unsigned int chr3)
{
  int result, is_first_col;
  int v6, v7, v8;
  int idx, v10;
  char *v11;
  int v13;

  result = 1LL;
  if ( chr3 != ' ' )
  {
    result = 0LL;
    if ( chr3 - '1' <= 8 )
    {
      is_first_col = chr1 - 3 < 3;
      v6 = 3 * is_first_col + 2;
      v7 = 3 * is_first_col;
      if ( chr1 - 6 < 3 )
        v7 = 6;
      if ( chr1 - 6 < 3 )
        v6 = 8;
      v8 = 3 * (chr2 - 3 < 3) + 2;
      if ( chr2 - 6 < 3 )
        v8 = 8;
      if ( v7 <= v6 )
      {
        v10 = 3 * (chr2 - 3 < 3);
        if ( chr2 - 6 < 3 )
          v10 = 6;
        v7 = v7;
        v11 = &inputbuf[9 * v7];
        while ( v10 > v8 )
        {
LABEL_32:
          v11 += 9;
          if ( v7++ >= v6 )
            goto LABEL_10;
        }
        v13 = v10 - 1LL;
        while ( v11[v13 + 1] != chr3 )
        {
          ++v13;
          ++v10;
          if ( v13 >= v8 )
            goto LABEL_32;
        }
      }
      else
      {
LABEL_10:
        idx = 9LL * chr1;
        if ( inputbuf[idx] != chr3
          && inputbuf[chr2] != chr3
          && inputbuf[idx + 1] != chr3
          && inputbuf[chr2 + 9] != chr3
          && inputbuf[idx + 2] != chr3
          && inputbuf[chr2 + 18] != chr3
          && inputbuf[idx + 3] != chr3
          && inputbuf[chr2 + 27] != chr3
          && inputbuf[idx + 4] != chr3
          && inputbuf[chr2 + 36] != chr3
          && inputbuf[idx + 5] != chr3
          && inputbuf[chr2 + 45] != chr3
          && inputbuf[idx + 6] != chr3
          && inputbuf[chr2 + 54] != chr3
          && inputbuf[idx + 7] != chr3
          && inputbuf[chr2 + 63] != chr3
          && inputbuf[idx + 8] != chr3 )
        {
          return inputbuf[chr2 + 72] != chr3;
        }
      }
    }
  }
  return result;
}

int main(int argc, char **a2)
{
  char *user_input;
  char v3;
  unsigned int input0;
  unsigned int input1;
  char input2;
  int v7;
  int i;
  char v10[8];
  char v11[81];

  if ( argc <= 1 )
  {
    printf("Usage : %s <serial>\n", *a2);
    exit(1);
  }
  user_input = a2[1];
  memcpy(v11, "                                                                                6", sizeof(v11));
  v11[10] = 50;
  *(short*)&v11[20] = 0x3933;
  v11[29] = 53;
  v11[36] = 55;
  *(short*)&v11[55] = 13877;
  v11[64] = 49;
  memcpy(&v11[3], "546", 3);
  *(short*)&v11[49] = 13113;
  v11[59] = 56;
  *(short*)&v11[67] = 14643;
  v11[8] = 57;
  v11[17] = 55;
  *(short*)&v11[26] = 14644;
  v11[34] = 55;
  v11[43] = 50;
  v11[78] = 56;
  v3 = *user_input;
  while ( 1 )
  {
    input0 = v3 - '1';
    input1 = user_input[1] - '1';
    input2 = user_input[2];
    if ( checksudoku(v11, input0, user_input[1] - '1', input2) )
    {

      puts("Good move");
      v11[9 * input0 + input1] = input2;
    }
    user_input += 3;
    v7 = 0;
    for ( i = 8LL; i != 89; i += 9LL )
      v7 += (v10[i] != 32)
          + (v10[i + 1] != 32)
          + (v10[i + 2] != 32)
          + (v10[i + 3] != 32)
          + (v10[i + 4] != 32)
          + (v10[i + 5] != 32)
          + (v10[i + 6] != 32)
          + (v10[i + 7] != 32)
          + (v11[i] != 32);
    if ( v7 == 81 )
      break;
    v3 = *user_input;
    if ( !*user_input )
    {
      puts("Nope.");
      printf("%81s\n", v11);
      return 1LL;
    }
  }
  puts("\nWell done ! You can validate with this flag : ");
  print_flag(v11);
  return 0LL;
}