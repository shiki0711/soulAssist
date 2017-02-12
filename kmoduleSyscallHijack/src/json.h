
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
/* rbtree extention for iterator */
extern struct rb_node *rb_left_deepest_node(const struct rb_node *);
extern struct rb_node *rb_next_postorder(const struct rb_node *);
extern struct rb_node *rb_first_postorder(const struct rb_root *);
#define rbtree_postorder_for_each_entry_safe(pos, n, root, field) \
  for (pos = rb_entry(rb_first_postorder(root), typeof(*pos), field),   \
         n = rb_entry(rb_next_postorder(&pos->field),                   \
                      typeof(*pos), field);                             \
       &pos->field;                                                     \
       pos = n,                                                         \
         n = rb_entry(rb_next_postorder(&pos->field),                   \
                      typeof(*pos), field))
/* iterator */
#define json_obj_for_each rbtree_postorder_for_each_entry_safe

/* array */
typedef struct json_array {
  struct list_head head;
  int cnt;
} json_array_t;
/* iterator */
#define json_array_for_each list_for_each_entry_safe


/* json instance type */
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

/* json parser */
extern json_t* json_parse(const char *);

/* json editor */
extern int json_add_int(json_t *, int);

/* release */
extern void json_release(json_t *);

/* json serialize */
extern char* json_serialize(json_t *);

/* debug */
extern void json_dump(json_t *);

#endif
