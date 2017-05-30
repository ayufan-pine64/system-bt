/******************************************************************************
 *
 *  Copyright (C) 1999-2012 Broadcom Corporation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

/******************************************************************************
 *
 *  this file contains the main Bluetooth Manager (BTM) internal
 *  definitions.
 *
 ******************************************************************************/

#ifndef BTM_BLE_INT_H
#define BTM_BLE_INT_H

#include "bt_common.h"
#include "bt_target.h"
#include "btm_ble_api.h"
#include "btm_ble_int_types.h"
#include "btm_int.h"
#include "btm_int_types.h"
#include "hcidefs.h"
#include "smp_api.h"


/* scanning enable status */
#define BTM_BLE_SCAN_ENABLE      0x01
#define BTM_BLE_SCAN_DISABLE     0x00

/* advertising enable status */
#define BTM_BLE_ADV_ENABLE     0x01
#define BTM_BLE_ADV_DISABLE    0x00

/* use the high 4 bits unused by inquiry mode */
#define BTM_BLE_SELECT_SCAN     0x20
#define BTM_BLE_NAME_REQUEST    0x40
#define BTM_BLE_OBSERVE         0x80

#define BTM_BLE_MAX_WL_ENTRY        1
#define BTM_BLE_AD_DATA_LEN         31

#define BTM_BLE_ENC_MASK    0x03

#define BTM_BLE_DUPLICATE_ENABLE        1
#define BTM_BLE_DUPLICATE_DISABLE       0

#define BTM_BLE_GAP_DISC_SCAN_INT      18         /* Interval(scan_int) = 11.25 ms= 0x0010 * 0.625 ms */
#define BTM_BLE_GAP_DISC_SCAN_WIN      18         /* scan_window = 11.25 ms= 0x0010 * 0.625 ms */
#define BTM_BLE_GAP_ADV_INT            512        /* Tgap(gen_disc) = 1.28 s= 512 * 0.625 ms */
#define BTM_BLE_GAP_LIM_TIMEOUT_MS     (180 * 1000) /* Tgap(lim_timeout) = 180s max */
#ifdef BLUETOOTH_RTK
#define BTM_BLE_LOW_LATENCY_SCAN_INT   18       /* Interval(scan_int) = 11.25ms = 18 * 0.625 ms */
#define BTM_BLE_LOW_LATENCY_SCAN_WIN   18       /* scan_window = 11.25ms = 18 * 0.625 ms */
#else
#define BTM_BLE_LOW_LATENCY_SCAN_INT   8000       /* Interval(scan_int) = 5s= 8000 * 0.625 ms */
#define BTM_BLE_LOW_LATENCY_SCAN_WIN   8000       /* scan_window = 5s= 8000 * 0.625 ms */
#endif

#define BTM_BLE_GAP_ADV_FAST_INT_1         48         /* TGAP(adv_fast_interval1) = 30(used) ~ 60 ms  = 48 *0.625 */
#define BTM_BLE_GAP_ADV_FAST_INT_2         160         /* TGAP(adv_fast_interval2) = 100(used) ~ 150 ms = 160 * 0.625 ms */
#define BTM_BLE_GAP_ADV_SLOW_INT           2048         /* Tgap(adv_slow_interval) = 1.28 s= 512 * 0.625 ms */
#define BTM_BLE_GAP_ADV_DIR_MAX_INT        800         /* Tgap(dir_conn_adv_int_max) = 500 ms = 800 * 0.625 ms */
#define BTM_BLE_GAP_ADV_DIR_MIN_INT        400         /* Tgap(dir_conn_adv_int_min) = 250 ms = 400 * 0.625 ms */

#define BTM_BLE_GAP_FAST_ADV_TIMEOUT_MS    (30 * 1000)

#define BTM_BLE_SEC_REQ_ACT_NONE           0
#define BTM_BLE_SEC_REQ_ACT_ENCRYPT        1 /* encrypt the link using current key or key refresh */
#define BTM_BLE_SEC_REQ_ACT_PAIR           2
#define BTM_BLE_SEC_REQ_ACT_DISCARD        3 /* discard the sec request while encryption is started but not completed */
typedef UINT8   tBTM_BLE_SEC_REQ_ACT;

#define BLE_STATIC_PRIVATE_MSB_MASK          0x3f
#define BLE_RESOLVE_ADDR_MSB                 0x40   /*  most significant bit, bit7, bit6 is 01 to be resolvable random */
#define BLE_RESOLVE_ADDR_MASK                0xc0   /* bit 6, and bit7 */
#define BTM_BLE_IS_RESOLVE_BDA(x)           ((x[0] & BLE_RESOLVE_ADDR_MASK) == BLE_RESOLVE_ADDR_MSB)

#define BLE_PUBLIC_ADDR_MSB_MASK            0xC0
#define BLE_PUBLIC_ADDR_MSB                 0x80   /*  most significant bit, bit7, bit6 is 10 to be public address*/
#define BTM_IS_PUBLIC_BDA(x)               ((x[0]  & BLE_PUBLIC_ADDR_MSB) == BLE_PUBLIC_ADDR_MSB_MASK)

/* LE scan activity bit mask, continue with LE inquiry bits */
#define BTM_LE_SELECT_CONN_ACTIVE      0x40     /* selection connection is in progress */
#define BTM_LE_OBSERVE_ACTIVE          0x80     /* observe is in progress */

/* BLE scan activity mask checking */
#define BTM_BLE_IS_SCAN_ACTIVE(x)   ((x) & BTM_BLE_SCAN_ACTIVE_MASK)
#define BTM_BLE_IS_INQ_ACTIVE(x)   ((x) & BTM_BLE_INQUIRY_MASK)
#define BTM_BLE_IS_OBS_ACTIVE(x)   ((x) & BTM_LE_OBSERVE_ACTIVE)
#define BTM_BLE_IS_SEL_CONN_ACTIVE(x)   ((x) & BTM_LE_SELECT_CONN_ACTIVE)

/* BLE ADDR type ID bit */
#define BLE_ADDR_TYPE_ID_BIT 0x02

#define BTM_VSC_CHIP_CAPABILITY_L_VERSION 55
#define BTM_VSC_CHIP_CAPABILITY_M_VERSION 95

typedef struct
{
    UINT16              data_mask;
    UINT8               *p_flags;
    UINT8               ad_data[BTM_BLE_AD_DATA_LEN];
    UINT8               *p_pad;
}tBTM_BLE_LOCAL_ADV_DATA;

typedef struct
{
    UINT32          inq_count;          /* Used for determining if a response has already been      */
                                        /* received for the current inquiry operation. (We do not   */
                                        /* want to flood the caller with multiple responses from    */
                                        /* the same device.                                         */
    BOOLEAN         scan_rsp;
    tBLE_BD_ADDR    le_bda;
} tINQ_LE_BDADDR;

#define BTM_BLE_ADV_DATA_LEN_MAX        31
#define BTM_BLE_CACHE_ADV_DATA_MAX      62

#define BTM_BLE_ISVALID_PARAM(x, min, max)  (((x) >= (min) && (x) <= (max)) || ((x) == BTM_BLE_CONN_PARAM_UNDEF))

/* 15 minutes minimum for random address refreshing */
#define BTM_BLE_PRIVATE_ADDR_INT_MS     (15 * 60 * 1000)

typedef struct
{
    UINT16 discoverable_mode;
    UINT16 connectable_mode;
    UINT32 scan_window;
    UINT32 scan_interval;
    UINT8 scan_type; /* current scan type: active or passive */
    UINT8 scan_duplicate_filter; /* duplicate filter enabled for scan */
    UINT16 adv_interval_min;
    UINT16 adv_interval_max;
    tBTM_BLE_AFP afp; /* advertising filter policy */
    tBTM_BLE_SFP sfp; /* scanning filter policy */

    tBLE_ADDR_TYPE adv_addr_type;
    UINT8 evt_type;
    UINT8 adv_mode;
    tBLE_BD_ADDR direct_bda;
    tBTM_BLE_EVT directed_conn;
    BOOLEAN fast_adv_on;
    alarm_t *fast_adv_timer;

    UINT8 adv_len;
    UINT8 adv_data_cache[BTM_BLE_CACHE_ADV_DATA_MAX];

    /* inquiry BD addr database */
    UINT8 num_bd_entries;
    UINT8 max_bd_entries;
    tBTM_BLE_LOCAL_ADV_DATA adv_data;
    tBTM_BLE_ADV_CHNL_MAP adv_chnl_map;

    alarm_t *inquiry_timer;
    BOOLEAN scan_rsp;
    UINT8 state; /* Current state that the inquiry process is in */
    INT8 tx_power;
} tBTM_BLE_INQ_CB;


/* random address resolving complete callback */
typedef void (tBTM_BLE_RESOLVE_CBACK) (void * match_rec, void *p);

typedef void (tBTM_BLE_ADDR_CBACK) (BD_ADDR_PTR static_random, void *p);

/* random address management control block */
typedef struct
{
    tBLE_ADDR_TYPE              own_addr_type;         /* local device LE address type */
    BD_ADDR                     private_addr;
    BD_ADDR                     random_bda;
    BOOLEAN                     busy;
    tBTM_BLE_ADDR_CBACK         *p_generate_cback;
    void                        *p;
    alarm_t                     *refresh_raddr_timer;
} tBTM_LE_RANDOM_CB;

#define BTM_BLE_MAX_BG_CONN_DEV_NUM    10

extern bool ble_evt_type_is_connectable(uint16_t evt_type);
extern void btm_ble_refresh_raddr_timer_timeout(void* data);
extern void btm_ble_process_adv_pkt(uint8_t len, uint8_t* p);
extern void btm_ble_process_phy_update_pkt(uint8_t len, uint8_t* p);
extern void btm_ble_process_ext_adv_pkt(uint8_t len, uint8_t* p);
extern void btm_ble_proc_scan_rsp_rpt(uint8_t* p);
extern tBTM_STATUS btm_ble_read_remote_name(BD_ADDR remote_bda,
                                            tBTM_CMPL_CB* p_cb);
extern bool btm_ble_cancel_remote_name(BD_ADDR remote_bda);

extern tBTM_STATUS btm_ble_set_discoverability(uint16_t combined_mode);
extern tBTM_STATUS btm_ble_set_connectability(uint16_t combined_mode);
extern void btm_send_hci_scan_enable(uint8_t enable, uint8_t filter_duplicates);
extern void btm_send_hci_set_scan_params(uint8_t scan_type, uint16_t scan_int,
                                         uint16_t scan_win,
                                         uint8_t addr_type_own,
                                         uint8_t scan_filter_policy);
extern tBTM_STATUS btm_ble_start_inquiry(uint8_t mode, uint8_t duration);
extern void btm_ble_stop_scan(void);
extern void btm_clear_all_pending_le_entry(void);

extern void btm_ble_stop_scan();
extern void btm_ble_stop_inquiry(void);
extern void btm_ble_init(void);
extern void btm_ble_connected(uint8_t* bda, uint16_t handle, uint8_t enc_mode,
                              uint8_t role, tBLE_ADDR_TYPE addr_type,
                              bool addr_matched);
extern void btm_ble_read_remote_features_complete(uint8_t* p);
extern void btm_ble_write_adv_enable_complete(uint8_t* p);
extern void btm_ble_conn_complete(uint8_t* p, uint16_t evt_len, bool enhanced);
extern void btm_read_ble_local_supported_states_complete(uint8_t* p,
                                                         uint16_t evt_len);
extern tBTM_BLE_CONN_ST btm_ble_get_conn_st(void);
extern void btm_ble_set_conn_st(tBTM_BLE_CONN_ST new_st);
extern tBTM_STATUS btm_ble_start_adv(void);
extern tBTM_STATUS btm_ble_stop_adv(void);
extern void btm_le_on_advertising_set_terminated(uint8_t* p, uint16_t length);
extern tBTM_STATUS btm_ble_start_scan(void);
extern void btm_ble_create_ll_conn_complete(uint8_t status);

/* LE security function from btm_sec.cc */
extern void btm_ble_link_sec_check(BD_ADDR bd_addr, tBTM_LE_AUTH_REQ auth_req,
                                   tBTM_BLE_SEC_REQ_ACT* p_sec_req_act);
extern void btm_ble_ltk_request_reply(BD_ADDR bda, bool use_stk,
                                      BT_OCTET16 stk);
extern uint8_t btm_proc_smp_cback(tSMP_EVT event, BD_ADDR bd_addr,
                                  tSMP_EVT_DATA* p_data);
extern tBTM_STATUS btm_ble_set_encryption(BD_ADDR bd_addr,
                                          tBTM_BLE_SEC_ACT sec_act,
                                          uint8_t link_role);
extern void btm_ble_ltk_request(uint16_t handle, uint8_t rand[8],
                                uint16_t ediv);
extern tBTM_STATUS btm_ble_start_encrypt(BD_ADDR bda, bool use_stk,
                                         BT_OCTET16 stk);
extern void btm_ble_link_encrypted(BD_ADDR bd_addr, uint8_t encr_enable);

/* LE device management functions */
extern void btm_ble_reset_id(void);

/* security related functions */
extern void btm_ble_increment_sign_ctr(BD_ADDR bd_addr, bool is_local);
extern bool btm_get_local_div(BD_ADDR bd_addr, uint16_t* p_div);
extern bool btm_ble_get_enc_key_type(BD_ADDR bd_addr, uint8_t* p_key_types);

extern void btm_ble_test_command_complete(uint8_t* p);
extern void btm_ble_rand_enc_complete(uint8_t* p, uint16_t op_code,
                                      tBTM_RAND_ENC_CB* p_enc_cplt_cback);

extern void btm_sec_save_le_key(BD_ADDR bd_addr, tBTM_LE_KEY_TYPE key_type,
                                tBTM_LE_KEY_VALUE* p_keys,
                                bool pass_to_application);
extern void btm_ble_update_sec_key_size(BD_ADDR bd_addr, uint8_t enc_key_size);
extern uint8_t btm_ble_read_sec_key_size(BD_ADDR bd_addr);

/* white list function */
extern bool btm_update_dev_to_white_list(bool to_add, BD_ADDR bd_addr);
extern void btm_update_scanner_filter_policy(tBTM_BLE_SFP scan_policy);
extern void btm_update_adv_filter_policy(tBTM_BLE_AFP adv_policy);
extern void btm_ble_clear_white_list(void);
extern void btm_read_white_list_size_complete(uint8_t* p, uint16_t evt_len);
extern void btm_ble_add_2_white_list_complete(uint8_t status);
extern void btm_ble_remove_from_white_list_complete(uint8_t* p,
                                                    uint16_t evt_len);
extern void btm_ble_clear_white_list_complete(uint8_t* p, uint16_t evt_len);
extern void btm_ble_white_list_init(uint8_t white_list_size);

/* background connection function */
extern bool btm_ble_suspend_bg_conn(void);
extern bool btm_ble_resume_bg_conn(void);
extern void btm_send_hci_create_connection(
    uint16_t scan_int, uint16_t scan_win, uint8_t init_filter_policy,
    uint8_t addr_type_peer, BD_ADDR bda_peer, uint8_t addr_type_own,
    uint16_t conn_int_min, uint16_t conn_int_max, uint16_t conn_latency,
    uint16_t conn_timeout, uint16_t min_ce_len, uint16_t max_ce_len,
    uint8_t phy);
extern bool btm_ble_start_auto_conn(bool start);
extern bool btm_ble_start_select_conn(bool start);
extern bool btm_ble_renew_bg_conn_params(bool add, BD_ADDR bd_addr);
extern void btm_write_dir_conn_wl(BD_ADDR target_addr);
extern void btm_ble_update_mode_operation(uint8_t link_role, BD_ADDR bda,
                                          uint8_t status);
extern bool btm_execute_wl_dev_operation(void);
extern void btm_ble_update_link_topology_mask(uint8_t role, bool increase);

/* direct connection utility */
extern bool btm_send_pending_direct_conn(void);
extern void btm_ble_enqueue_direct_conn_req(void* p_param);
extern void btm_ble_dequeue_direct_conn_req(BD_ADDR rem_bda);

/* BLE address management */
extern void btm_gen_resolvable_private_addr(base::Callback<void(BT_OCTET8)> cb);
extern void btm_gen_non_resolvable_private_addr(tBTM_BLE_ADDR_CBACK* p_cback,
                                                void* p);
extern tBTM_SEC_DEV_REC* btm_ble_resolve_random_addr(BD_ADDR random_bda);
extern void btm_gen_resolve_paddr_low(BT_OCTET8 rand);

/*  privacy function */
#if (BLE_PRIVACY_SPT == TRUE)
/* BLE address mapping with CS feature */
extern bool btm_identity_addr_to_random_pseudo(BD_ADDR bd_addr,
                                               uint8_t* p_addr_type,
                                               bool refresh);
extern bool btm_random_pseudo_to_identity_addr(BD_ADDR random_pseudo,
                                               uint8_t* p_static_addr_type);
extern void btm_ble_refresh_peer_resolvable_private_addr(BD_ADDR pseudo_bda,
                                                         BD_ADDR rra,
                                                         uint8_t rra_type);
extern void btm_ble_refresh_local_resolvable_private_addr(BD_ADDR pseudo_addr,
                                                          BD_ADDR local_rpa);
extern void btm_ble_read_resolving_list_entry_complete(uint8_t* p,
                                                       uint16_t evt_len);
extern void btm_ble_remove_resolving_list_entry_complete(uint8_t* p,
                                                         uint16_t evt_len);
extern void btm_ble_add_resolving_list_entry_complete(uint8_t* p,
                                                      uint16_t evt_len);
extern void btm_ble_clear_resolving_list_complete(uint8_t* p, uint16_t evt_len);
extern void btm_read_ble_resolving_list_size_complete(uint8_t* p,
                                                      uint16_t evt_len);
extern void btm_ble_enable_resolving_list(uint8_t);
extern bool btm_ble_disable_resolving_list(uint8_t rl_mask, bool to_resume);
extern void btm_ble_enable_resolving_list_for_platform(uint8_t rl_mask);
extern void btm_ble_resolving_list_init(uint8_t max_irk_list_sz);
extern void btm_ble_resolving_list_cleanup(void);
#endif

extern void btm_ble_adv_init(void);
extern void* btm_ble_multi_adv_get_ref(uint8_t inst_id);
extern void btm_ble_multi_adv_cleanup(void);
extern void btm_ble_batchscan_init(void);
extern void btm_ble_batchscan_cleanup(void);
extern void btm_ble_adv_filter_init(void);
extern void btm_ble_adv_filter_cleanup(void);
extern bool btm_ble_topology_check(tBTM_BLE_STATE_MASK request);
extern bool btm_ble_clear_topology_mask(tBTM_BLE_STATE_MASK request_state);
extern bool btm_ble_set_topology_mask(tBTM_BLE_STATE_MASK request_state);
extern void btm_ble_set_random_address(BD_ADDR random_bda);

#if (BTM_BLE_CONFORMANCE_TESTING == TRUE)
extern void btm_ble_set_no_disc_if_pair_fail(bool disble_disc);
extern void btm_ble_set_test_mac_value(bool enable, uint8_t* p_test_mac_val);
extern void btm_ble_set_test_local_sign_cntr_value(
    bool enable, uint32_t test_local_sign_cntr);
extern void btm_ble_set_keep_rfu_in_auth_req(bool keep_rfu);
#endif

#endif
