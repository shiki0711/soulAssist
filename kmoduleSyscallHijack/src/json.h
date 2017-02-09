
#ifndef __JSON_H__
#define __JSON_H__


/* stack */
typedef struct stack {
  int array[32];
  int corsur;
} stack_t;

static inline void stack_init(stack_t *stk) {
  stk->corsur = -1;
}

static inline int stack_push(stack_t *stk, int value) {
  if(stk->corsur >= 32) return -1;
  stk->array[++stk->corsur] = value;
  return 0;
}

static inline int stack_top(stack_t *stk, int *value) {
  if(stk->corsur < 0) return -1;
  *value = stk->array[stk->corsur];
  return 0;
}

static inline int stack_pop(stack_t *stk, int *value) {
  if(stk->corsur < 0) return -1;
  *value = stk->array[stk->corsur--];
  return 0;
}


/* json */
enum {
  json_type_int,
  json_type_double,
  json_type_string,
  json_type_bool,
  json_type_null,
  json_type_array,
  json_type_object
};

/* obj */
typedef struct json_obj {
  struct rb_root root;
} json_obj_t;

/* array */
typedef struct json_array {
  struct list_head head;
} json_array_t;


typedef struct json {
  char type;
  char *key;
  union {
    long i;
    char *s;
    double f;
    json_obj_t *o;
    json_array_t *a;
  } value;
  char lntype;
  union {
    struct list_head li;
    struct rb_node tr;
  } link;
} json_t;



#endif
