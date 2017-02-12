
#include <stdio.h>
#include <string.h>

#include "rbtree.h"
#include "list.h"
#include "json.h"



int main(int argc, const char *argv[]){
  json_t *j;
  j = json_parse("{}");
  json_release(j);

  j = json_parse(" { \"id\" : \"yanfeng\" , \"name\" : \"\\\" 12345678  \\\"\" } ");
  json_dump(j);
  json_release(j);

  j = json_parse("{\"info\":{\"id\":\"yanfeng\",\"name\":\"xyz\", \"n1\":0, \"n2\":1, \"n3\":-1, \"n4\": 10, \"n5\": -999999, \"n6\":0.2, \"n7\": -0.2, \"n8\": 10.0, \"n9\": -10.0, \"m1\":1e2, \"m2\":-0.2e-500, \"m3\":-1.56E+40}}");
  json_dump(j);
  json_release(j);

  j = json_parse(" [ {\"id\": 2, \"list\": [] }, [1, 2, \"xyz\"], 1,  true, false, null, \"abcd\" , -1.0 ] ");
  json_dump(j);
  json_release(j);

  char *pBuff = calloc(1, 4*1024*1024);
  if(!pBuff){
    printf("malloc error!\n");
    return -1;
  }
  FILE *fp = fopen(argv[1], "r");
  if(!fp){
    printf("fopen error!\n");
    return -1;
  }
  size_t ret = fread(pBuff, 1024*1024, 4, fp);
  j = json_parse(pBuff);
  json_dump(j);
  json_release(j);
  free(pBuff);
  fclose(fp);

  return 0;
}

