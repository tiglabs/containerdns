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
        node = xalloc_zero(sizeof *node);
    }

    /* init node */
    node->parent = NULL;
    node->left = NULL;
    node->right = NULL;
    node->view_data = VIEW_NULL_VALUE;

    return node;
}


static view_node_t* do_view_tree_get(view_tree_t *tree, uint8_t *key, size_t nbits, int flags)
{
    uint8_t bit = 0x80; 
    size_t byte = 0;    

    view_node_t *cur = tree->root;
    view_node_t *last = NULL; 

    /* walk down the tree */
    while (cur && nbits-- > 0) {
        if (cur->view_data != VIEW_NULL_VALUE) {
            if (flags & FIND_FIRST) {
                return cur;
            }
            if (flags & FIND_BEST) {
                last = cur; 
            }
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

    if (!cur && (flags & FIND_BEST)) {
        return last;
    }

    return cur;
}

static int do_view_tree_insert(view_tree_t *tree, uint8_t *key, size_t nbits, char *pcidr, char *view_name)
{
    view_value_t *view_data = (view_value_t *)xalloc_zero(sizeof(view_value_t));
    if (view_data == NULL) {
        log_msg(LOG_ERR, "no mem for caloc :%s--%s\n", pcidr, view_name);
        return -1;
    }

    view_node_t *node = do_view_tree_get(tree, key, nbits, CREATE);
    if (node->view_data != VIEW_NULL_VALUE) {
        log_msg(LOG_ERR, "warning: insert duplicate view tree node!\n");
        free(view_data);
        return -1;
    }

    memcpy(view_data->cidrs, pcidr, strlen(pcidr));
    memcpy(view_data->view_name, view_name, strlen(view_name));
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

static int do_view_tree_delete(view_tree_t *tree, uint8_t *key, size_t nbits, char *pcidr, char *view_name)
{
    view_node_t *node = do_view_tree_get(tree, key, nbits, 0);
    if (node == NULL || node->view_data == VIEW_NULL_VALUE) {
        log_msg(LOG_ERR, "warning: delete non-exist key in view tree!\n");
        return -1;
    }
    if (strcmp(node->view_data->cidrs, pcidr) || strcmp(node->view_data->view_name, view_name)) {
        log_msg(LOG_ERR, "warning: cidrs %s or view_name %s different with cidrs %s or view_name %s in view tree!\n",
            pcidr, view_name, node->view_data->cidrs, node->view_data->view_name);
        return -1;
    }

    free(node->view_data);
    node->view_data = VIEW_NULL_VALUE;
    tree->size--;

    if (node->left || node->right || (node->parent == NULL)) {
        return 0;
    }
    while (!node->left && !node->right) {
        if (node->parent->left == node) {
            node->parent->left = NULL;
        } else {
            node->parent->right = NULL;
        }

        node->right = tree->free;
        tree->free = node;
        node = node->parent;
        tree->free->parent = NULL;
        if (node->view_data != VIEW_NULL_VALUE || node->parent == NULL) {
            break;
        }
    }
    return 0;
}

view_tree_t *view_tree_create(void)
{
    view_tree_t *tree = xalloc_zero(sizeof *tree);

    tree->free = NULL;
    tree->size = 0;
    tree->root = view_tree_alloc_node(tree);

    return tree;
}

int view_operate(view_tree_t *tree, char *pcidr, char *view_name, enum view_action action)
{
    int ret = -1;
    size_t nbits = 32, maxbits = 32;

    if (action != ACTION_ADD && action != ACTION_DEL) {
        log_msg(LOG_ERR, "action %d is not valid!\n", action);
        return -1;
    }
    char *cidr = strdup(pcidr);
    char *mask = strchr(cidr, '/'); 
    if (mask != NULL) {
        *mask = '\0';
        mask++;

        nbits = atoi(mask);
        if (nbits <= 0 || nbits >= maxbits) {
            log_msg(LOG_ERR, "mask bits '%s' is not valid!\n", mask);
            goto _out;
        }
    }
    //check the addr
    struct in_addr ip;
    if (inet_pton(AF_INET, cidr, &ip) != 1) {
        log_msg(LOG_ERR, "ipv4 addr '%s' is not valid!\n", cidr);
        goto _out;
    }

    if (action == ACTION_ADD) {
        ret = do_view_tree_insert(tree, (uint8_t *)&ip.s_addr, nbits, pcidr, view_name);
        if (ret != 0) {
            log_msg(LOG_ERR, "failed to insert view_name %s, cidr %s in view tree!\n", view_name, cidr);
        }
    } else {
        ret = do_view_tree_delete(tree, (uint8_t *)&ip.s_addr, nbits, pcidr, view_name);
        if (ret != 0) {
            log_msg(LOG_ERR, "failed to delete view_name %s, cidr %s from view tree!\n", view_name, cidr);
        }
    }

_out:
    free(cidr);
    return ret;
}

void view_tree_dump(view_node_t *node, void* arg1, void (*callback)(void*, view_value_t *))
{
    if (node->view_data != VIEW_NULL_VALUE) {
        callback(arg1, node->view_data);
    }
    if (node->left) {
        view_tree_dump(node->left, arg1, callback);
    }
    if (node->right) {
        view_tree_dump(node->right, arg1, callback);
    }
}
