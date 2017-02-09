
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
  
  return 0;
}

