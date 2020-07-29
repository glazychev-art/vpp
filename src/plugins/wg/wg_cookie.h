/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef __included_wg_cookie_h__
#define __included_wg_cookie_h__

#include <vnet/ip/ip4_packet.h>
#include <wg/wg_noise.h>

//typedef struct cookie_checker
//{
//  u8 secret[NOISE_HASH_LEN];
//  u8 cookie_encryption_key[NOISE_SYMMETRIC_KEY_LEN];
//  u8 message_mac1_key[NOISE_SYMMETRIC_KEY_LEN];
//  u64 secret_birthdate;
//} cookie_checker_t;

//typedef struct cookie
//{
//  u64 birthdate;
//  bool is_valid;
//  u8 cookie[COOKIE_LEN];
//  bool have_sent_mac1;
//  u8 last_mac1_sent[COOKIE_LEN];
//  u8 cookie_decryption_key[NOISE_SYMMETRIC_KEY_LEN];
//  u8 message_mac1_key[NOISE_SYMMETRIC_KEY_LEN];
//} cookie_t;

enum cookie_mac_state
{
  INVALID_MAC,
  VALID_MAC_BUT_NO_COOKIE,
  VALID_MAC_WITH_COOKIE
};

//void wg_cookie_init (cookie_t * cookie);

//void wg_cookie_checker_init (cookie_checker_t * checker, f64 now);

//void wg_cookie_checker_precompute_keys (cookie_checker_t * checker,
//                    struct noise_local *
//                    local);

//void wg_cookie_checker_precompute_peer_keys (wg_peer_t * peer);
//void wg_cookie_add_mac_to_packet (void *message, size_t len,
//				  wg_peer_t * peer, f64 now);

//void wg_cookie_message_consume (vlib_main_t * vm,
//				const wg_index_table_t * table,
//				wg_peer_t * peer_pool,
//				message_handshake_cookie_t * src);


//enum cookie_mac_state wg_cookie_validate_packet (vlib_main_t * vm,
//						 cookie_checker_t * checker,
//						 void *message, size_t len,
//						 ip4_address_t ip4,
//						 u16 udp_src,
//						 bool check_cookie);


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////_______NEW__REALIZATION_______////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define COOKIE_MAC_SIZE		16
#define COOKIE_KEY_SIZE		32
#define COOKIE_NONCE_SIZE	XCHACHA20POLY1305_NONCE_SIZE
#define COOKIE_COOKIE_SIZE	16
#define COOKIE_SECRET_SIZE	32
#define COOKIE_INPUT_SIZE	32
#define COOKIE_ENCRYPTED_SIZE	(COOKIE_COOKIE_SIZE + COOKIE_MAC_SIZE)

#define COOKIE_MAC1_KEY_LABEL	"mac1----"
#define COOKIE_COOKIE_KEY_LABEL	"cookie--"
#define COOKIE_SECRET_MAX_AGE	120
#define COOKIE_SECRET_LATENCY	5

/* Constants for initiation rate limiting */
#define RATELIMIT_SIZE		(1 << 13)
#define RATELIMIT_SIZE_MAX	(RATELIMIT_SIZE * 8)
#define NSEC_PER_SEC		1000000000LL
#define INITIATIONS_PER_SECOND	20
#define INITIATIONS_BURSTABLE	5
#define INITIATION_COST		(NSEC_PER_SEC / INITIATIONS_PER_SECOND)
#define TOKEN_MAX		(INITIATION_COST * INITIATIONS_BURSTABLE)
#define ELEMENT_TIMEOUT		1
#define IPV4_MASK_SIZE		4 /* Use all 4 bytes of IPv4 address */
#define IPV6_MASK_SIZE		8 /* Use top 8 bytes (/64) of IPv6 address */

struct cookie_macs {
    uint8_t	mac1[COOKIE_MAC_SIZE];
    uint8_t	mac2[COOKIE_MAC_SIZE];
};

struct cookie_maker {
    uint8_t		cp_mac1_key[COOKIE_KEY_SIZE];
    uint8_t		cp_cookie_key[COOKIE_KEY_SIZE];

    uint8_t		cp_cookie[COOKIE_COOKIE_SIZE];
    f64	        cp_birthdate;
    int		     cp_mac1_valid;
    uint8_t		cp_mac1_last[COOKIE_MAC_SIZE];
};

struct cookie_checker {
    //struct ratelimit	cc_ratelimit_v4;

    uint8_t			cc_mac1_key[COOKIE_KEY_SIZE];
    uint8_t			cc_cookie_key[COOKIE_KEY_SIZE];

    f64		        cc_secret_birthdate;
    uint8_t			cc_secret[COOKIE_SECRET_SIZE];
};


void	cookie_maker_init(struct cookie_maker *, uint8_t[COOKIE_INPUT_SIZE]);
//int	cookie_checker_init(struct cookie_checker *, struct pool *);
void	cookie_checker_update(struct cookie_checker *,
        uint8_t[COOKIE_INPUT_SIZE]);
//void	cookie_checker_deinit(struct cookie_checker *);
//void	cookie_checker_create_payload(struct cookie_checker *,
//        struct cookie_macs *cm, uint8_t[COOKIE_NONCE_SIZE],
//        uint8_t [COOKIE_ENCRYPTED_SIZE], struct sockaddr *);
bool	cookie_maker_consume_payload(vlib_main_t * vm, struct cookie_maker *,
        uint8_t[COOKIE_NONCE_SIZE], uint8_t[COOKIE_ENCRYPTED_SIZE]);
void	cookie_maker_mac(struct cookie_maker *, message_macs_t *,
        void *, size_t);
enum cookie_mac_state cookie_checker_validate_macs(vlib_main_t * vm, struct cookie_checker *,
        message_macs_t *, void *, size_t, bool, ip4_address_t ip4, u16 udp_port);


#endif /* __included_wg_cookie_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
