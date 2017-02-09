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
#define json_calloc(...) calloc(__VA_ARGS__)
#define json_free(p) free(p)
#define hook_debug(...) printf(__VA_ARGS__);

#endif /* __UT__ */

#include "json.h"

#define GOTO_ERR(LABLE, ...) {hook_debug(__VA_ARGS__);goto LABLE;}

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
static struct rb_node *rb_left_deepest_node(const struct rb_node *node) {
  for (;;) {
    if (node->rb_left)
      node = node->rb_left;
    else if (node->rb_right)
      node = node->rb_right;
    else
      return (struct rb_node *)node;
  }
}

static struct rb_node *rb_next_postorder(const struct rb_node *node) {
  const struct rb_node *parent;
  if (!node)
    return NULL;
  parent = rb_parent(node);

  if (parent && node == parent->rb_left && parent->rb_right) {
    return rb_left_deepest_node(parent->rb_right);
  }else
    return (struct rb_node *)parent;
}

static struct rb_node *rb_first_postorder(const struct rb_root *root) {
  if (!root->rb_node)
    return NULL;
  return rb_left_deepest_node(root->rb_node);
}

#define rbtree_postorder_for_each_entry_safe(pos, n, root, field) \
  for (pos = rb_entry(rb_first_postorder(root), typeof(*pos), field),   \
         n = rb_entry(rb_next_postorder(&pos->field),                   \
                      typeof(*pos), field);                             \
       &pos->field;                                                     \
       pos = n,                                                         \
         n = rb_entry(rb_next_postorder(&pos->field),                   \
                      typeof(*pos), field))


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
    snprintf(p, 128-lv, "key:%s value(int):%ld\n", entry->key, entry->value.i);
    hook_debug("%s", buff);
    break;
  case json_type_double:
    snprintf(p, 128-lv, "key:%s value(double):%f\n", entry->key, entry->value.f);
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
    /* TODO */
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

  if(entry->key) json_free(entry->key);
  switch(entry->type){
  case json_type_string:
    if(entry->value.s) json_free(entry->value.s);
    break;
  case json_type_int:
  case json_type_double:
    break;
  case json_type_object:
    rbtree_postorder_for_each_entry_safe(pos, n, &(entry->value.o->root), link.tr){
      json_release(pos);
    }
    break;
  case json_type_array:
    /* TODO */
    break;
  }
  json_free(entry);
}


#define NEW_ENTRY(_entry, _parent, _stk, _key, _errlb ) {        \
    _parent = NULL;                                     \
    stack_top(&_stk, (int*)(&_parent));                 \
    _entry = json_calloc(1, sizeof(json_t));                        \
    if(!_entry) GOTO_ERR(_errlb, "json parser no enough memory\n"); \
    if(stack_push(&_stk, (int)_entry)) GOTO_ERR(_errlb, "json parser stack overflow!\n"); \
    if(_parent) {                                                       \
      if(_parent->lntype == json_lntype_list) {                         \
        list_add_tail(&(_entry->link.li), &(_parent->value.a->head));   \
      }else {                                                     \
        _entry->key = _key;                                       \
        json_obj_insert(_parent->value.o, _entry);                \
      }                                                           \
    }                                                             \
  }

#define NEW_OBJECT(_rt, _errlb) {                                \
    _rt = json_calloc(1, sizeof(struct rb_root));                \
    if(!_rt) GOTO_ERR(_errlb, "json parser no enough memory\n"); \
  }

#define NEW_STRING(_p, _s1, _s2, _errlb) {                      \
    _p = json_calloc(1, (_s2-_s1+1));                           \
    if(!_p) GOTO_ERR(_errlb, "json parser no enough memory\n"); \
    strncpy(_p, _s1, (_s2-_s1));                                \
  }

static inline int is_escape(const char *s) {
  int i = 0;

  while((*(--s)) == '\\'){
    ++i;
  }
  return (i%2);
}

json_t* json_parse(const char *in) {
  int i=0;
  char c;
  int sts = 0;
  json_t *entry = NULL, *parent = NULL;
  stack_t sts_stk, entry_stk;
  const char *s1 = NULL, *s2 = NULL;
  char *t = NULL;

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
        stack_pop(&entry_stk, &sts);
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
      if(is_space(c)){
        goto L_continue;
      }
      if(c=='"'){
        /* string */
        stack_pop(&sts_stk, &sts);
        stack_push(&sts_stk, json_sts_string);
        s1 = in + i + 1;
      }else if(c=='{'){
        /* object */
      }else if(c=='['){
        /* array */
      }else if(c=='t' || c=='f'){
        /* boolean */
      }else if(c=='n'){
        /* nil */
      }else if(c=='-' || (c>='0' && c<= '9')){
        /* number */
      }
      break;

    case json_sts_string:
      if(c=='"' && !is_escape(in+i)){
        stack_pop(&sts_stk, &sts);
        stack_push(&sts_stk, json_sts_value_fin);
        s2 = in + i;
        stack_top(&entry_stk, (int*)(&entry));
        if(s2 >= s1){
          NEW_STRING(entry->value.s, s1, s2, L_parse_err);
          entry->type = json_type_string;
        }
        stack_pop(&entry_stk, &sts);
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
        stack_pop(&sts_stk, &sts);
        stack_top(&entry_stk, (int*)(&entry));
        if(entry->type != json_type_object){
          GOTO_ERR(L_parse_err, "json format error, un-paired object brackets\n");
        }
        stack_pop(&sts_stk, &sts);
        stack_pop(&entry_stk, &sts);
      }else if(c==']'){
        stack_pop(&sts_stk, &sts);
        stack_top(&entry_stk, (int*)(&entry));
        if(entry->type != json_type_array){
          GOTO_ERR(L_parse_err, "json format error, un-paired array brackets\n");
        }
        stack_pop(&sts_stk, &sts);
        stack_pop(&entry_stk, &sts);
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
    stack_top(&sts_stk, &sts);
    if(sts == json_sts_start){
      stack_pop(&sts_stk, &sts);
      stack_push(&sts_stk, json_sts_fin);
    }
        
    L_continue:
    ++i;
  }
  stack_top(&sts_stk, &sts);
  stack_top(&entry_stk, (int*)&entry);
  if(sts == json_sts_fin){
    return entry;
  }

 L_parse_err:
  json_release(entry);
  return NULL;
}



