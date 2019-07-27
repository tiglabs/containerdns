#ifndef _RATE_LIMIT_H_
#define _RATE_LIMIT_H_

typedef enum {
    RATE_LIMIT_TYPE_ALL,
    RATE_LIMIT_TYPE_FWD,
    RATE_LIMIT_TYPE_EXCEEDED_LOG,
    RATE_LIMIT_TYPE_MAX,
} rate_limit_type;

int rate_limit(uint32_t sip, rate_limit_type type, unsigned lcore_id);

int rate_limit_init(uint32_t all_per_second, uint32_t fwd_per_second, uint32_t client_num, unsigned lcore_id);

void rate_limit_uninit(unsigned lcore_id);

int rate_limit_reload(uint32_t all_per_second, uint32_t fwd_per_second, uint32_t client_num, unsigned lcore_id);

#endif  /* _RATE_LIMIT_H_ */

