/*
 *
 * Copyright (c) 2018 The TIGLabs Authors.
 *
 */

#ifndef __DNS_VIEW_H__
#define __DNS_VIEW_H__

#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "kdns.h"



#define VIEW_NULL_VALUE NULL
#define VIEW_NO_NODE    NULL



/* type of stored value */

typedef struct view_value{
    char  cidrs[MAX_VIEW_NAME_LEN];
    char  view_name[MAX_VIEW_NAME_LEN];
}view_value_t;


typedef struct _view_node {
    struct _view_node *left;
    struct _view_node *right;
    struct _view_node *parent;
    view_value_t * view_data;
} view_node_t;

typedef struct view_tree {
    view_node_t *root;
    view_node_t *free; 
    int size;
} view_tree_t;

int view_insert(view_tree_t *tree,char *pcidr, char *view_name);
int view_delete(view_tree_t *tree,char *pcidr);
view_tree_t *view_tree_create(void);
view_value_t* view_find(view_tree_t *tree, uint8_t *key, size_t nbits);
void view_tree_dump(view_node_t *node,  void* arg1,void (*callback)(void*,view_value_t *));





#endif
