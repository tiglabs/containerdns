/*
 *
 * Copyright (c) 2018 The TIGLabs Authors.
 *
 */

#include <jansson.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "view.h"
#include "kdns.h"

#define CREATE      0x1  
#define FIND_FIRST  0x2 
#define FIND_BEST   0x4  

static view_node_t *view_tree_alloc_node(view_tree_t *tree)
{
    view_node_t *node;

    if (tree->free) {
        node = tree->free;
        tree->free = node->right;
    } else {
        node = calloc(sizeof *node, 1);
    }

    /* init node */
    node->parent = NULL;
    node->left = NULL;
    node->right = NULL;
    node->view_data = VIEW_NULL_VALUE;

    return node;
}


static view_node_t* do_view_tree_get(view_tree_t *tree,
        uint8_t *key, size_t nbits, int flags)
{
    uint8_t bit = 0x80; 
    size_t byte = 0;    

    view_node_t *cur = tree->root;
    view_node_t *last = NULL; 

    /* walk down the tree */
    while (cur && nbits-- > 0) {
        if (cur->view_data != VIEW_NULL_VALUE) {
            if (flags & FIND_FIRST)
                return cur;
            if (flags & FIND_BEST)
                last = cur; 
        }

        if (bit & key[byte]) {
            if (cur->right == NULL && (flags & CREATE)) {
                cur->right = view_tree_alloc_node(tree);
                cur->right->parent = cur;
            }
            cur = cur->right;
        } else { 
            if (cur->left == NULL && (flags & CREATE)) {
                cur->left = view_tree_alloc_node(tree);
                cur->left->parent = cur;
            }
            cur = cur->left;
        }

        bit >>= 1; 

        if (bit == 0) {
            bit = 0x80;
            byte++;
        }
    }

    if (!cur && (flags & FIND_BEST))
        return last;

    return cur;
}

static int do_view_tree_insert(view_tree_t *tree, uint8_t *key, size_t nbits,
        view_value_t *view_data)
{
    view_node_t *node = do_view_tree_get(tree, key, nbits, CREATE);

    if (node->view_data != VIEW_NULL_VALUE) {
        fprintf(stderr, "warning: insert duplicate view tree node!\n");
        return -1;
    }

    /* set view_name */
    node->view_data = view_data;

    tree->size++;

    return 0;
}

view_value_t* view_find(view_tree_t *tree, uint8_t *key, size_t nbits)
{
    view_node_t *node = do_view_tree_get(tree, key, nbits, FIND_BEST);

    return node ? node->view_data : VIEW_NO_NODE;
}

static int do_view_tree_delete(view_tree_t *tree, uint8_t *key, size_t nbits)
{
    view_node_t *node = do_view_tree_get(tree, key, nbits, 0);

    if (node == NULL || node->view_data == VIEW_NULL_VALUE) {
        fprintf(stderr, "warning: delete non-exist key in view tree!\n");
        return -1;
    }

    if (node->left || node->right || (node->parent == NULL)) {
        node->view_data = VIEW_NULL_VALUE;
        tree->size--;
        return 0;
    }


    while (!node->left && !node->right) {
        if (node->parent->left == node)
            node->parent->left = NULL;
        else
            node->parent->right = NULL;

        node->right = tree->free;
        tree->free = node;


        node = node->parent;

        if (node->view_data != VIEW_NULL_VALUE){ 
            free(node->view_data);
            break;
        }

        if (node->parent == NULL) 
            break;
    }

    tree->size--;

    return 0;
}

view_tree_t *view_tree_create(void)
{
    view_tree_t *tree = calloc(sizeof *tree, 1);

    tree->free = NULL;
    tree->size = 0;
    tree->root = view_tree_alloc_node(tree);

    return tree;
}


int view_delete(view_tree_t *tree,char *pcidr){

    int ret = 0;
    size_t nbits = 32, maxbits = 32;

    char *cidr = strdup(pcidr);

    char *mask = strchr(cidr, '/'); 
    if (mask != NULL) {
        *mask = '\0';
        mask++;

        nbits = atoi(mask);
        if (nbits <= 0 || nbits >= maxbits) {
            log_msg(LOG_ERR, "mask bits '%s' is not valid!", mask); 
            ret = -1;
            goto error;
        }
    }
    //check the addr
    struct in_addr ip;
    if (inet_pton(AF_INET, cidr, &ip) != 1) {
        log_msg(LOG_ERR, "ipv4 addr '%s' is not valid!", cidr); 
        ret = -1;
        goto error;
    }

  do_view_tree_delete(tree, (uint8_t *) &ip.s_addr, nbits); 
   
error:
    free(cidr);

    return ret;
}

int view_insert(view_tree_t *tree,char *pcidr, char *view_name){

    int ret = 0;
    size_t nbits = 32, maxbits = 32;
    
    char *cidr = strdup(pcidr);

    view_value_t *view_data = (view_value_t *)calloc(1,sizeof(view_value_t));
    if (view_data == NULL){
          log_msg(LOG_ERR, "no mem for caloc :%s--%s\n", pcidr,view_name); 
            ret = -1;
            goto error;
    }

    char *mask = strchr(cidr, '/'); 
    if (mask != NULL) {
        *mask = '\0';
        mask++;

        nbits = atoi(mask);
        if (nbits <= 0 || nbits >= maxbits) {
            log_msg(LOG_ERR, "mask bits '%s' is not valid!", mask); 
            ret = -1;
            goto error;
        }
    }
    //check the addr
    struct in_addr ip;
    if (inet_pton(AF_INET, cidr, &ip) != 1) {
        log_msg(LOG_ERR, "ipv4 addr '%s' is not valid!", cidr); 
        ret = -1;
        goto error;
    }

    memcpy(view_data->cidrs, pcidr, strlen(pcidr));
    memcpy(view_data->view_name, view_name, strlen(view_name));

    do_view_tree_insert(tree, (uint8_t *) &ip.s_addr, nbits, view_data); 
   
error:
    free(cidr);

    return ret;
}

void view_tree_dump(view_node_t *node,  void* arg1,void (*callback)(void*,view_value_t *))
{
    if (node->view_data != VIEW_NULL_VALUE) {
        callback(arg1,node->view_data);
    }

    if (node->left) {
        view_tree_dump(node->left,arg1, callback);
    }

    if (node->right) {
        view_tree_dump(node->right,arg1,callback);
    }
}
