#include <rte_rwlock.h>
#include <string.h>
#include <stdio.h>
#include "hashMap.h"
#include "util.h"

unsigned int elfHashDomain(char *str) {
    unsigned int len = strlen(str);
    unsigned int hash = 0;
    unsigned int x = 0;
    unsigned int i = 0;
    for (i = 0; i < len; str++, i++) {
        hash = (hash << 4) + (*str);
        if ((x = hash & 0xF0000000L) != 0) {
            hash ^= (x >> 24);
        }
        hash &= ~x;
    }
    return hash;
}

void hmap_update(hashMap *map, char *key, void *check, void *new_data) {
    hashNode *find;

    int hashValue = map->hashFun(key);
    int hashId = hashValue & map->bucketsSize;
    int lockId = hashId & map->lockSize;

    rte_rwlock_write_lock(&map->locks[lockId]);

    find = map->hashBuckets[hashId];
    while (find) {
        if ((find->fingerprint == hashValue) && (map->equalFun(key, find, check))) {
            break;
        }
        find = find->next;
    }
    if (find == NULL) {
        //add to head
        hashNode *newNode = xalloc_zero(sizeof(hashNode));
        newNode->fingerprint = hashValue;
        newNode->key = strdup(key);
        newNode->data = new_data;
        newNode->next = map->hashBuckets[hashId];
        map->hashBuckets[hashId] = newNode;
    } else {
        free(find->data);
        find->data = new_data;
    }
    rte_rwlock_write_unlock(&map->locks[lockId]);
}

int hmap_check_expired(hashMap *map, void *arg) {
    hashNode *pre = NULL;
    hashNode *node = NULL;
    hashNode *node_del = NULL;
    if (map->checkExpiredFun == NULL) {
        log_msg(LOG_INFO, "hmap_check_expired:  checkExpiredFun is null \n");
        return -1;
    }
    unsigned int hashId = 0;
    unsigned int lockId = 0;
    unsigned int del_num = 0;

    for (; hashId < map->bucketsSize; hashId++) {
        lockId = hashId & map->lockSize;
        rte_rwlock_write_lock(&map->locks[lockId]);
        pre = node = map->hashBuckets[hashId];
        while (node) {
            if (map->checkExpiredFun(node, arg)) {
                if (node == map->hashBuckets[hashId]) {
                    map->hashBuckets[hashId] = node->next;
                    pre = map->hashBuckets[hashId];
                } else {
                    pre->next = node->next;
                }
                node_del = node;
                node = node->next;
                free(node_del->key);
                free(node_del->data);
                free(node_del);
                del_num++;
                continue;
            }
            pre = node;
            node = node->next;
        }
        rte_rwlock_write_unlock(&map->locks[lockId]);
    }
    if (del_num) {
        log_msg(LOG_INFO, "hmap_check_expired:%d record dels \n", del_num);
    }
    return del_num;
}

int hmap_get_all(hashMap *map, void *arg) {
    hashNode *node = NULL;
    if (map->getAllNodeFun == NULL) {
        log_msg(LOG_INFO, "hmap_get_all:  getAllNodeFun is null \n");
        return -1;
    }
    unsigned int hashId = 0;
    unsigned int lockId = 0;

    for (; hashId < map->bucketsSize; hashId++) {
        lockId = hashId & map->lockSize;
        rte_rwlock_read_lock(&map->locks[lockId]);
        node = map->hashBuckets[hashId];
        while (node) {
            map->getAllNodeFun(node, arg);
            node = node->next;
        }
        rte_rwlock_read_unlock(&map->locks[lockId]);
    }
    return 0;
}

int hmap_lookup(hashMap *map, char *key, void *check, void *arg) {
    hashNode *find;
    int ret = -1;

    int hashValue = map->hashFun(key);
    int hashId = hashValue & map->bucketsSize;
    int lockId = hashId & map->lockSize;

    rte_rwlock_read_lock(&map->locks[lockId]);
    find = map->hashBuckets[hashId];
    while (find) {
        if ((find->fingerprint == hashValue) && (map->equalFun(key, find, check))) {
            break;
        }
        find = find->next;
    }
    if (find != NULL) {
        map->queryFun(find, arg);
        ret = HASH_NODE_FIND;
    }
    rte_rwlock_read_unlock(&map->locks[lockId]);
    return ret;
}

void hmap_del(hashMap *map, char *key, void *check) {
    hashNode *pre;
    hashNode *find;

    int hashValue = map->hashFun(key);
    int hashId = hashValue & map->bucketsSize;
    int lockId = hashId & map->lockSize;

    rte_rwlock_write_lock(&map->locks[lockId]);
    pre = find = map->hashBuckets[hashId];

    while (find) {
        if ((find->fingerprint == hashValue) && (map->equalFun(key, find, check))) {
            break;
        }
        pre = find;
        find = find->next;
    }

    if (find != NULL && pre != NULL) {
        if (find == map->hashBuckets[hashId]) {
            map->hashBuckets[hashId] = find->next;
        } else {
            pre->next = find->next;
        }
        free(find->key);
        free(find->data);
        free(find);
    }
    rte_rwlock_write_unlock(&map->locks[lockId]);
}

void hmap_del_all(hashMap *map) {
    hashNode *node_del = NULL;

    unsigned int hashId = 0;
    unsigned int lockId = 0;
    unsigned int del_num = 0;

    for (; hashId < map->bucketsSize; hashId++) {
        lockId = hashId & map->lockSize;
        rte_rwlock_write_lock(&map->locks[lockId]);
        while (map->hashBuckets[hashId]) {
            node_del = map->hashBuckets[hashId];
            map->hashBuckets[hashId] = map->hashBuckets[hashId]->next;
            free(node_del->key);
            free(node_del->data);
            free(node_del);
            del_num++;
        }
        rte_rwlock_write_unlock(&map->locks[lockId]);
    }
    if (del_num) {
        log_msg(LOG_INFO,"hmap_del_all:%d record dels\n", del_num);
    }
}

static int check_config_size(int a) {
    int b = a + 1;
    if ((a & b) == 0) {
        return 1;
    }
    return 0;
}

hashMap *hmap_create(int bucketsSize, int lockSize,
                     unsigned int (*hashFun)(char *key),
                     int (*equalFun)(char *key, hashNode *node, void *check),
                     int (*queryFun)(hashNode *node, void *arg),
                     int (*checkExpiredFun)(hashNode *node, void *arg),
                     int (*getAllNodeFun)(hashNode *node, void *arg)) {

    if (check_config_size(bucketsSize) == 0) {
        log_msg(LOG_ERR, "bucketsSize :%d must be power of 2 minus one \n", bucketsSize);
        exit(0);
    }
    if (check_config_size(lockSize) == 0) {
        log_msg(LOG_ERR, "lockSize:%d must be power of 2 minus one \n", lockSize);
        exit(0);
    }

    hashMap *newMap = (hashMap *)xalloc_zero(sizeof(hashMap));

    newMap->bucketsSize = bucketsSize;
    newMap->lockSize = lockSize;
    newMap->hashFun = hashFun;
    newMap->equalFun = equalFun;
    newMap->queryFun = queryFun;
    newMap->checkExpiredFun = checkExpiredFun;
    newMap->getAllNodeFun = getAllNodeFun;
    newMap->hashBuckets = (hashNode **)xalloc_zero(bucketsSize * sizeof(hashNode *));
    newMap->locks = (rte_rwlock_t *)xalloc_zero(lockSize * sizeof(rte_rwlock_t));
    unsigned int i = 0;
    for (; i < newMap->lockSize; i++) {
        rte_rwlock_init(&newMap->locks[i]);
    }
    return newMap;
}
