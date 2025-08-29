#ifndef BL602_PORT_H
#define BL602_PORT_H

int mbedtls_hardware_poll(void *data,
    unsigned char *output, size_t len, size_t *olen);
    
#endif // BL602_PORT_H