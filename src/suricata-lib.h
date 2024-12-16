/**
 * Simple encapsulation of suricata-7.0.2 as a shared library.
 * @date    2024-12-16
 * @author  ifindv@gmail.com
 */

#ifndef __SURICATA_LIB_H__
#define __SURICATA_LIB_H__
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** 
 * initialize suricata library instance, load configuration and start process.
 * @param name
 *  suricata library instance name, distinguish diffrent processes.
 * @param ips
 *  work mode as a IPS or IDS engine.
 * @return
 *  0 on success, -1 for an error.
*/
int suricata_init(const char *name, bool ips);

/**
 * process input packet and ouput detect result.
 * @param pkt
 *  input packet start address (from ether header).
 * @param len
 *  length of input packet.
 * @param res
 *  output detect result.
 * @return
 *  0 on success, -1 for an error.
 */
int suricata_proc(void *pkt, int len, void *res);

/**
 * (re)load suricata rules after suricata initialized.
 * @return
 *  0 on success, -1 for an error.
 */
int suricata_load(void);

/**
 * suricata library instance deinit, free system resources.
 * @return
 *  0 on success, -1 for an error.
 */
int suricata_exit(void);

#ifdef __cplusplus
}
#endif

/* vim: set expandtab shiftwidth=4 tabstop=4: */
