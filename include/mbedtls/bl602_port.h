#ifndef BL602_PORT_H
#define BL602_PORT_H


// timer structure
struct mbedtls_timing_hr_time {
    uint32_t start_time;
};

/**
 * \brief          Context for mbedtls_timing_set/get_delay()
 */
typedef struct mbedtls_timing_delay_context {
    struct mbedtls_timing_hr_time   timer;
    uint32_t                        int_ms;
    uint32_t                        fin_ms;
} mbedtls_timing_delay_context;

int mbedtls_hardware_poll(void *data,
    unsigned char *output, size_t len, size_t *olen);
    
#endif // BL602_PORT_H