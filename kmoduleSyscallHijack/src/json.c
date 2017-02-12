#ifndef __UT__

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/rbtree.h>
#include <linux/slab.h>

#include "dbg.h"

#define json_calloc(...) kcalloc(__VA_ARGS__, GFP_KERNEL)
#define json_free(p) kfree(p)

#else /* __UT__ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h" 
#include "rbtree.h"
#include "list.h"
int ggg=0;
#define json_calloc(...) calloc(__VA_ARGS__);
#define json_free(p) free(p)
#define hook_debug(...) printf(__VA_ARGS__)

#endif /* __UT__ */

#include "json.h"

#define GOTO_ERR(LABLE, ...) {hook_debug(__VA_ARGS__); goto LABLE;}

enum {
  json_sts_start,
  json_sts_key_start,
  json_sts_key_string,
  json_sts_key_fin,
  json_sts_colon,
  json_sts_comma,
  json_sts_value_fin,
  json_sts_string,
  json_sts_array,
  json_sts_obj,
  json_sts_number,
  json_sts_bool,
  json_sts_null,
  json_sts_fin
};

enum {
  json_lntype_list,
  json_lntype_rbtree,
  json_lntype_none
};

/* json_object */
int json_obj_insert(json_obj_t *jsonobj,  json_t *data) {
  struct rb_node **new = &(jsonobj->root.rb_node), *parent = NULL;
  json_t *this = NULL;
  int result = 0;

  /* Figure out where to put new node */
  while (*new) {
    this = container_of(*new, json_t, link.tr);
    result = strncmp(data->key, this->key, strlen(data->key));

    parent = *new;
    if (result < 0)
      new = &((*new)->rb_left);
    else if (result > 0)
      new = &((*new)->rb_right);
    else
      return 0;
  }

  /* Add new node and rebalance tree. */
  rb_link_node(&data->link.tr, parent, new);
  rb_insert_color(&data->link.tr, &jsonobj->root);

  return 1;
}

json_t *json_obj_find(json_obj_t *jsonobj, const char *key){
  struct rb_node *node = jsonobj->root.rb_node;
  json_t *data = NULL;
  int result = 0;

  while (node) {
    data = container_of(node, json_t, link.tr);
    result = strcmp(data->key, key);

    if (result < 0)
      node = node->rb_left;
    else if (result > 0)
      node = node->rb_right;
    else
      return data;
  }
  return NULL;
}

/* rbtree extention */
struct rb_node *rb_left_deepest_node(const struct rb_node *node) {
  for (;;) {
    if (node->rb_left)
      node = node->rb_left;
    else if (node->rb_right)
      node = node->rb_right;
    else
      return (struct rb_node *)node;
  }
}

struct rb_node *rb_next_postorder(const struct rb_node *node) {
  const struct rb_node *parent;
  if (!node)
    return NULL;
  parent = rb_parent(node);

  if (parent && node == parent->rb_left && parent->rb_right) {
    return rb_left_deepest_node(parent->rb_right);
  }else
    return (struct rb_node *)parent;
}

struct rb_node *rb_first_postorder(const struct rb_root *root) {
  if (!root->rb_node)
    return NULL;
  return rb_left_deepest_node(root->rb_node);
}

/* json array */
int json_array_insert(json_array_t *jsonary,  json_t *data) {
  list_add_tail(&(data->link.li), &(jsonary->head));
  jsonary->cnt++;
  return 1;
}

json_t* json_array_find(json_array_t *jsonary, int idx) {
  json_t *pos = NULL, *n = NULL;
  if(jsonary->cnt <= idx) return NULL;
  list_for_each_entry_safe(pos, n, &(jsonary->head), link.li){
    if(!idx--) break;
  }
  return pos;
}


/* debug */
void json_dump(json_t *entry){
  json_t *pos, *n;
  static int lv = -1;
  char buff[128] = {0};
  char *p = buff;
  int i;

  ++lv;
  
  for(i=0; i<lv; ++i){
    *p++ = ' ';
  }
  switch(entry->type){
  case json_type_string:
    snprintf(p, 128-lv, "key:%s value(string):%s\n", entry->key, entry->value.s);
    hook_debug("%s", buff);
    break;
  case json_type_int:
    snprintf(p, 128-lv, "key:%s value(int):%s\n", entry->key, entry->value.s);
    hook_debug("%s", buff);
    break;
  case json_type_double:
    snprintf(p, 128-lv, "key:%s value(double):%s\n", entry->key, entry->value.s);
    hook_debug("%s", buff);
    break;
  case json_type_object:
    snprintf(p, 128-lv, "key:%s value(object):\n", entry->key);
    hook_debug("%s", buff);
    rbtree_postorder_for_each_entry_safe(pos, n, &(entry->value.o->root), link.tr){
     json_dump(pos);
    }
    break;
  case json_type_array:
    snprintf(p, 128-lv, "key:%s value(array):\n", entry->key);
    hook_debug("%s", buff);
    list_for_each_entry_safe(pos, n, &(entry->value.a->head), link.li){
      json_dump(pos);
    }
    break;
  case json_type_bool:
    snprintf(p, 128-lv, "key:%s value(boolean):%s\n", entry->key, entry->value.i?"true":"false");
    hook_debug("%s", buff);
    break;
  case json_type_null:
    snprintf(p, 128-lv, "key:%s value(null):%s\n", entry->key, "null");
    hook_debug("%s", buff);
    break;
  }
  --lv;
}

/* json paser */
static inline int is_space(char c) {
  return (c==' ' || c=='\t' || c=='\r' || c=='\n');
}

void json_release(json_t *entry) {
  json_t *pos, *n;

  if(!entry) return;

  if(entry->key) json_free(entry->key);
  switch(entry->type){
  case json_type_string:
    if(entry->value.s) json_free(entry->value.s);
    break;
  case json_type_int:
  case json_type_double:
    if(entry->value.s) json_free(entry->value.s);
    break;
  case json_type_object:
    rbtree_postorder_for_each_entry_safe(pos, n, &(entry->value.o->root), link.tr){
      json_release(pos);
    }
    json_free(entry->value.o);
    break;
  case json_type_array:
    list_for_each_entry_safe(pos, n, &(entry->value.a->head), link.li){
      json_release(pos);
    }
    json_free(entry->value.s);
    break;
  }
  json_free(entry);
}


#define NEW_ENTRY(_entry, _parent, _stk, _key, _errlb ) {               \
    (_parent) = NULL;                                                   \
    stack_top(&(_stk), (int*)(&(_parent)));                             \
    (_entry) = json_calloc(1, sizeof(json_t));                          \
    if(!(_entry)) GOTO_ERR(_errlb, "json parser no enough memory\n");   \
    if(stack_push(&(_stk), (int)(_entry))) GOTO_ERR(_errlb, "json parser stack overflow!\n"); \
    if((_parent)) {                                                     \
      if((_parent)->lntype == json_lntype_list) {                       \
        json_array_insert((_parent)->value.a, (_entry));                \
      }else {                                                           \
        (_entry)->key = (_key);                                         \
        json_obj_insert((_parent)->value.o, (_entry));                  \
      }                                                                 \
    }                                                                   \
  }

#define NEW_OBJECT(_rt, _errlb) {                                       \
    (_rt) = json_calloc(1, sizeof(json_obj_t));                         \
    if(!(_rt)) GOTO_ERR(_errlb, "json parser no enough memory\n");      \
  }

#define NEW_ARRAY(_li, _errlb) {                                        \
    (_li) = json_calloc(1, sizeof(json_array_t));                       \
    if(!(_li)) GOTO_ERR(_errlb, "json parser no enough memory\n");      \
    INIT_LIST_HEAD(&((_li)->head));                                     \
    (_li)->cnt = 0;                                                     \
  }

#define NEW_STRING(_p, _s1, _s2, _errlb) {                              \
    (_p) = json_calloc(1, ((_s2)-(_s1)+1));                             \
    if(!(_p)) GOTO_ERR(_errlb, "json parser no enough memory\n");       \
    strncpy((_p), (_s1), ((_s2)-(_s1)));                                \
  }

#define PROC_FIN(_stk, _sts, _errlb) {           \
    if(stack_top(&(_stk), &(_sts))) GOTO_ERR(_errlb, "json parser stack 0!\n"); \
    if((_sts) == json_sts_start){                                       \
      stack_push(&(_stk), json_sts_fin);                                \
    }else{                                                              \
      stack_push(&(_stk), json_sts_value_fin);                          \
    }                                                                   \
  }

static inline int is_escape(const char *s) {
  int i = 0;

  while((*(--s)) == '\\'){
    ++i;
  }
  return (i%2);
}

static inline int is_endofvalue(char c) {
  return (c==' ' || c=='\t' || c=='\r' || c=='\n' || c==',' || c=='}' || c==']');
}

/*
 * reutrn value:
 * -1: error
 * 0: int
 * 1: double
*/
static int parse_number(const char *s, int *len) {
  /*
    number:
    int
    int frac
    int exp
    int frac exp

    int:
    digit
    digit1-9 digits 
    - digit
    - digit1-9 digits

    frac:
    . digits

    exp:
    e digits

    digits:
    digit
    digit digits

    e:
    e
    e+
    e-
    E
    E+
    E-
   */
  
  /* parse number state */
  enum {
    _s_init,
    _s_minus,
    _s_int1,
    _s_int2,
    _s_frac_dot,
    _s_exp_e,
    _s_exp_p
  };
  /* number type */
  enum {
    _t_init,
    _t_int,
    _t_frac,
    _t_exp
  };

  char c = 0;
  int i = 0;
  int type = _t_init;
  int sts = _s_init;
  
  *len = 0;
  while((c=s[i])){
    switch(c){
    case '-':
      if(type == _t_init && sts == _s_init){
        type = _t_int;
        sts = _s_minus;
      }else if(type == _t_exp && sts == _s_exp_e){
        sts = _s_exp_p;
      }else{
        return -1;
      }
      break;

    case '+':
      if(type == _t_exp && sts == _s_exp_e){
        sts = _s_exp_p;
      }else{
        return -1;
      }
      break;

    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      if(type == _t_init || type == _t_int){
        if(sts == _s_int1 && s[i-1] == '0'){
          return -1;
        }
        if(sts == _s_init || sts == _s_minus) {
          sts = _s_int1;
        }else if(sts == _s_int1 || sts == _s_int2) {
          sts = _s_int2;
        }else{
          return -1;
        }
        type = _t_int;
      }else if(type == _t_frac){
        if(sts == _s_frac_dot || sts == _s_int2){
          sts = _s_int2;
        }else{
          return -1;
        }
      }else if(type == _t_exp){
        if(sts == _s_exp_e || sts == _s_exp_p || sts == _s_int2){
          sts = _s_int2;
        }else{
          return -1;
        }
      }else{
        return -1;
      }
      break;

    case '.':
      if(type != _t_int) {
        return -1;
      }
      if(sts == _s_int1 || sts == _s_int2) {
        sts = _s_frac_dot;
        type = _t_frac;
      }else{
        return -1;
      }
      break;

    case 'e':
    case 'E':
      if(type == _t_int){
        if(sts == _s_int1 || sts == _s_int2){
          type = _t_exp;
          sts = _s_exp_e;
        }else{
          return -1;
        }
      }else if(type == _t_frac){
        if(sts == _s_int2){
          type = _t_exp;
          sts = _s_exp_e;
        }else{
          return -1;
        }
      }else{
        return -1;
      }
      break;

    case ' ':
      
    default:
      if(is_endofvalue(c)){
        goto _L_fin;
      }else{
        return -1;
      }
      break;
    }
    ++i;
  }
 _L_fin:
  if(type == _t_int){
    if(sts == _s_int1 || sts == _s_int2){
      *len = i;
      return 0;
    }
  }else if(type == _t_frac || type == _t_exp){
    if(sts == _s_int2){
      *len = i;
      return 1;
    }
  }
  return -1;
}

/*
 * return value:
 * -1: parse error
 * 0: false
 * 1: true
 */
static int parse_boolean(const char *s, int *len){
  char c;
  int i = 0;
  char expect_char[2][6] = {
    {'f', 'a', 'l', 's', 'e', 0},
    {'t', 'r', 'u', 'e', 0}
  };
  int expect = -1;
  int idx = 0;

  while((c=s[i])){
    if(expect == -1){
      if(c==expect_char[0][idx]){
        expect = 0;
      }else if(c==expect_char[1][idx]){
        expect = 1;
      }else{
        return -1;
      }
    }else{
      if(expect_char[expect][idx]){
        if(expect_char[expect][idx] != c){
          return -1;
        }
      }else{
        /* matched */
        if(is_endofvalue(c)){
          *len = i;
          return expect;
        }else{
          return -1;
        }
      }
    }
    ++idx;
    ++i;
  }
  return -1;
}

/*
 * return value:
 * -1: parse error
 * 0: parsr ok
 */
static int parse_null(const char *s, int *len){
  char c;
  int i = 0;
  char expect_char[] = {'n', 'u', 'l', 'l', 0};
  int idx = 0;

  while((c=s[i])){
    if(expect_char[idx]){
      if(expect_char[idx] != c){
        return -1;
      }
    }else{
      /* matched */
      if(is_endofvalue(c)){
        *len = i;
        return 0;
      }else{
        return -1;
      }
    }
    ++idx;
    ++i;
  }
  return -1;
}

json_t* json_parse(const char *in) {
  int i = 0;
  char c;
  int sts = 0;
  json_t *entry = NULL, *parent = NULL;
  stack_t sts_stk, entry_stk;
  const char *s1 = NULL, *s2 = NULL;
  char *t = NULL;
  int len = 0;
  int type;

  stack_init(&sts_stk);
  stack_push(&sts_stk, json_sts_start);
  stack_init(&entry_stk);
  
  while((c=in[i])){
    if(stack_top(&sts_stk, &sts)){
      GOTO_ERR(L_parse_err, "json parser stack overflow, maybe there is some format error in json string!\n");
    }
    switch(sts){
    case json_sts_start:
      if(is_space(c)){
        goto L_continue;
      }else if(c=='{'){
        /* new object entry */
        NEW_ENTRY(entry, parent, entry_stk, "", L_parse_err);
        entry->type = json_type_object;
        entry->lntype = json_lntype_rbtree;
        NEW_OBJECT(entry->value.o, L_parse_err);
        /* new state */
        stack_push(&sts_stk, json_sts_obj);
      }else if(c == '['){
        /* new array entry */
        NEW_ENTRY(entry, parent, entry_stk, "", L_parse_err);
        entry->type = json_type_array;
        entry->lntype = json_lntype_list;
        NEW_ARRAY(entry->value.a, L_parse_err);
        /* new state */
        stack_push(&sts_stk, json_sts_array);
      }else{
        GOTO_ERR(L_parse_err, "json format error, json string should begin with a '[' or '{'\n");
      }
      break;

    case json_sts_obj:
      if(is_space(c)){
        goto L_continue;
      }else if(c =='"'){
        if(stack_push(&sts_stk, json_sts_key_start)) GOTO_ERR(L_parse_err, "json parser stack overflow!\n");
      }else if(c=='}'){
        stack_pop(&sts_stk, &sts);
        stack_pop(&entry_stk, (int*)&entry);
        PROC_FIN(sts_stk, sts, L_parse_err);
      }else{
        GOTO_ERR(L_parse_err, "json format error, a key should begin with '\"'\n");
      }
      break;

    case json_sts_key_start:
      if(c=='"'){
        if(!is_escape(in + i)) GOTO_ERR(L_parse_err, "json format error, a key should not a nil string\n");
      }
      /* TODO(yanfeng): check control-character */
      stack_pop(&sts_stk, &sts);
      stack_push(&sts_stk, json_sts_key_string);
      s1 = in + i;
      break;

    case json_sts_key_string:
      if(c=='"' && !is_escape(in + i)){
        stack_pop(&sts_stk, &sts);
        stack_push(&sts_stk, json_sts_key_fin);
        s2 = in + i;
        NEW_STRING(t, s1, s2, L_parse_err);
        /* new entry */
        NEW_ENTRY(entry, parent, entry_stk, t, L_parse_err);
      }else{
        /* TODO(yanfeng): check control-character */
      }
      break;

    case json_sts_key_fin:
      if(is_space(c)){
        goto L_continue;
      }else if(c==':'){
        stack_pop(&sts_stk, &sts);
        stack_push(&sts_stk, json_sts_colon);        
      }else{
        GOTO_ERR(L_parse_err, "json format error, no ':' character followed with a key!\n");
      }
      
      break;

    case json_sts_colon:
    case json_sts_array:
      if(is_space(c)){
        goto L_continue;
      }
      if(c=='"'){
        /* string */
        if(sts != json_sts_array){
          stack_pop(&sts_stk, &sts);
        }
        stack_push(&sts_stk, json_sts_string);
        s1 = in + i + 1;
      }else if(c=='{'){
        /* object */
        if(sts == json_sts_array){
          NEW_ENTRY(entry, parent, entry_stk, "", L_parse_err);
        }else{
          stack_top(&entry_stk, (int*)&entry);
          stack_pop(&sts_stk, &sts);
        }
        entry->type = json_type_object;
        entry->lntype = json_lntype_rbtree;
        NEW_OBJECT(entry->value.o, L_parse_err);
        /* new state */
        stack_push(&sts_stk, json_sts_obj);
      }else if(c=='['){
        /* array */
        if(sts == json_sts_array){
          NEW_ENTRY(entry, parent, entry_stk, "", L_parse_err);
        }else{
          stack_top(&entry_stk, (int*)&entry);
          stack_pop(&sts_stk, &sts);
        }
        entry->type = json_type_array;
        entry->lntype = json_lntype_list;
        NEW_ARRAY(entry->value.a, L_parse_err);
        /* new state */
        stack_push(&sts_stk, json_sts_array);
      }else if(c=='t' || c=='f'){
        /* boolean */
        if((type=parse_boolean(in+i, &len)) == -1){
          GOTO_ERR(L_parse_err, "json format error, illegal value!\n");
        }
        if(sts != json_sts_array){
          stack_pop(&sts_stk, &sts);
        }else{
          NEW_ENTRY(entry, parent, entry_stk, "", L_parse_err);
        }
        stack_pop(&entry_stk, (int*)(&entry));
        stack_push(&sts_stk, json_sts_value_fin);
        entry->type = json_type_bool;
        entry->value.i = type;
        /* since we inc i at L_continue, here we use len-1 */
        i += (len-1);
        goto L_continue;
      }else if(c=='n'){
        /* nil */
        if(parse_null(in+i, &len) == -1){
          GOTO_ERR(L_parse_err, "json format error, illegal value!\n");
        }
        if(sts != json_sts_array){
          stack_pop(&sts_stk, &sts);
        }else{
          NEW_ENTRY(entry, parent, entry_stk, "", L_parse_err);
        }
        stack_pop(&entry_stk, (int*)(&entry));
        stack_push(&sts_stk, json_sts_value_fin);
        entry->type = json_type_null;
        /* since we inc i at L_continue, here we use len-1 */
        i += (len-1);
        goto L_continue;
      }else if(c=='-' || (c>='0' && c<= '9')){
        /* number */
        if((type=parse_number(in+i, &len)) == -1){
          GOTO_ERR(L_parse_err, "json format error, illegal number!\n");
        }
        /* TODO(yanfeng):
         * string -> int/double transformation
         */
        if(sts != json_sts_array){
          stack_pop(&sts_stk, &sts);
        }else{
          NEW_ENTRY(entry, parent, entry_stk, "", L_parse_err);
        }
        stack_pop(&entry_stk, (int*)(&entry));
        stack_push(&sts_stk, json_sts_value_fin);
        /* since floating number operation inside kernel is not recommended,
         * we temporarily store number value as a string
        */
        NEW_STRING(entry->value.s, in+i, in+i+len, L_parse_err);
        if(type==0){
          entry->type = json_type_int;
        }else{
          entry->type = json_type_double;
        }
        /* since we inc i at L_continue, here we use len-1 */
        i += (len-1);
        goto L_continue;
      }else if(c==']'){
        if(sts != json_sts_array){
          GOTO_ERR(L_parse_err, "json format error, un-paired array brackets!\n");
        }
        stack_pop(&sts_stk, &sts);
        stack_pop(&entry_stk, (int*)(&entry));
        if(entry->type != json_type_array){
          GOTO_ERR(L_parse_err, "json format error, un-paired array brackets\n");
        }
        PROC_FIN(sts_stk, sts, L_parse_err);
      }else{
        GOTO_ERR(L_parse_err, "json format error, illegal value!\n");
      }
      break;

    case json_sts_string:
      if(c=='"' && !is_escape(in+i)){
        stack_pop(&sts_stk, &sts);
        stack_top(&sts_stk, &sts);
        if(sts == json_sts_array){
          NEW_ENTRY(entry, parent, entry_stk, "", L_parse_err);
        }
        stack_pop(&entry_stk, (int*)(&entry));
        stack_push(&sts_stk, json_sts_value_fin);
        s2 = in + i;
        if(s2 >= s1){
          NEW_STRING(entry->value.s, s1, s2, L_parse_err);
          entry->type = json_type_string;
        }
      }else{
        /* TODO(yanfeng): check control-character */
      }

      break;

    case json_sts_value_fin:
      if(is_space(c)){
        goto L_continue;
      }
      if(c==','){
        stack_pop(&sts_stk, &sts);
      }else if(c=='}'){
        stack_pop(&sts_stk, &sts);  /* json_sts_value_fin */
        stack_pop(&entry_stk, (int*)(&entry));
        if(entry->type != json_type_object){
          GOTO_ERR(L_parse_err, "json format error, un-paired object brackets\n");
        }
        stack_pop(&sts_stk, &sts);  /* json_sts_obj */
        PROC_FIN(sts_stk, sts, L_parse_err);
      }else if(c==']'){
        stack_pop(&sts_stk, &sts);  /* json_sts_value_fin */
        stack_pop(&entry_stk, (int*)(&entry));
        if(entry->type != json_type_array){
          GOTO_ERR(L_parse_err, "json format error, un-paired array brackets\n");
        }
        stack_pop(&sts_stk, &sts);  /* json_sts_array */
        PROC_FIN(sts_stk, sts, L_parse_err);
      }else{
        GOTO_ERR(L_parse_err, "json format error, expect comma or tail of object/array!\n");
      }
      break;

    case json_sts_fin:
      if(is_space(c)){
        goto L_continue;
      }else{
        GOTO_ERR(L_parse_err, "json format error, un-expect character after top json object string\n");
      }
      break;
    }
    
    /* fin checking */
    //    stack_top(&sts_stk, &sts);
    //    if(sts == json_sts_fin){
    //      stack_pop(&sts_stk, &sts);
    //      stack_push(&sts_stk, json_sts_fin);
    //    }
        
    L_continue:
    ++i;
  }
  stack_top(&sts_stk, &sts);
  //stack_top(&entry_stk, (int*)&entry);
  if(sts == json_sts_fin){
    return entry;
  }

 L_parse_err:
  json_release(entry);
  return NULL;
}



