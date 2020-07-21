/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef __included_wg_noise_h__
#define __included_wg_noise_h__

#include <vlib/vlib.h>
#include <wg/wg_index_table.h>

typedef struct wg_peer wg_peer_t;

union noise_counter
{
  struct
  {
    u64 counter;
    unsigned long backtrack[COUNTER_BITS_TOTAL / BITS_PER_LONG];
  } receive;
  u64 counter;
};

typedef struct noise_symmetric_key
{
  u8 key[NOISE_SYMMETRIC_KEY_LEN];
  union noise_counter counter;
  f64 birthdate;
  bool is_valid;
} noise_symmetric_key_t;

typedef struct noise_keypair
{
  noise_symmetric_key_t sending;
  noise_symmetric_key_t receiving;
  u32 remote_index;
  u32 local_index;
  bool i_am_the_initiator;
  u64 internal_id;
} noise_keypair_t;

typedef struct noise_keypairs
{
  noise_keypair_t *current_keypair;
  noise_keypair_t *previous_keypair;
  noise_keypair_t *next_keypair;
} noise_keypairs_t;

typedef struct noise_static_identity
{
  u8 static_public[NOISE_PUBLIC_KEY_LEN];
  u8 static_private[NOISE_PUBLIC_KEY_LEN];
  bool has_identity;
} noise_static_identity_t;

enum noise_handshake_state
{
  HANDSHAKE_ZEROED,
  HANDSHAKE_CREATED_INITIATION,
  HANDSHAKE_CONSUMED_INITIATION,
  HANDSHAKE_CREATED_RESPONSE,
  HANDSHAKE_CONSUMED_RESPONSE
};

typedef struct noise_handshake
{
  wg_peer_t *peer;

  enum noise_handshake_state state;

  noise_static_identity_t *static_identity;

  u8 ephemeral_private[NOISE_PUBLIC_KEY_LEN];
  u8 remote_static[NOISE_PUBLIC_KEY_LEN];
  u8 remote_ephemeral[NOISE_PUBLIC_KEY_LEN];
  u8 precomputed_static_static[NOISE_PUBLIC_KEY_LEN];

  u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN];

  u8 hash[NOISE_HASH_LEN];
  u8 chaining_key[NOISE_HASH_LEN];

  u8 latest_timestamp[NOISE_TIMESTAMP_LEN];
  u32 remote_index;

  u32 local_index;
} noise_handshake_t;

void wg_noise_init ();
void wg_noise_handshake_init (wg_peer_t * peer,
			      noise_static_identity_t * static_identity,
			      const u8 peer_public_key[NOISE_PUBLIC_KEY_LEN],
			      const u8
			      peer_preshared_key[NOISE_SYMMETRIC_KEY_LEN]);
void wg_noise_handshake_clear (noise_handshake_t * handshake);
static inline void
wg_noise_reset_last_sent_handshake (f64 * handshake_time, f64 now)
{
  *handshake_time = now - (REKEY_TIMEOUT + 1);
}

void wg_noise_keypairs_clear (noise_keypairs_t * keypairs);
bool wg_noise_received_with_keypair (wg_index_table_t * table,
				     noise_keypairs_t * keypairs,
				     noise_keypair_t * new_keypair);
void wg_noise_set_static_identity_private_key (noise_static_identity_t *
					       static_identity,
					       const u8
					       private_key
					       [NOISE_PUBLIC_KEY_LEN]);

void wg_noise_precompute_static_static (noise_handshake_t * handshake);

bool
wg_noise_handshake_create_initiation (vlib_main_t * vm,
				      message_handshake_initiation_t * dst,
				      wg_peer_t * peer,
				      wg_index_table_t * index_table,
				      wg_peer_t * peer_pool);
wg_peer_t
  * wg_noise_handshake_consume_initiation (message_handshake_initiation_t *
					   src,
					   noise_static_identity_t *
					   static_identify,
					   wg_peer_t * peer_pool);

wg_peer_t *wg_noise_handshake_consume_response (message_handshake_response_t *
						src,
						noise_static_identity_t *
						static_identify,
						wg_index_table_t *
						index_table,
						wg_peer_t * peer_pool);

bool wg_noise_handshake_create_response (message_handshake_response_t * dst,
					 wg_peer_t * peer,
					 wg_index_table_t * index_table,
					 wg_peer_t * peer_pool);

bool wg_noise_handshake_begin_session (vlib_main_t * vm,
				       noise_handshake_t * handshake,
				       noise_keypairs_t * keypairs);


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////_______NEW__REALIZATION_______////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

enum noise_state_hs {
    HS_ZEROED = 0,
    CREATED_INITIATION,
    CONSUMED_INITIATION,
    CREATED_RESPONSE,
    CONSUMED_RESPONSE,
};

struct noise_handshake {
    enum noise_state_hs	 hs_state;
    uint32_t		 hs_local_index;
    uint32_t		 hs_remote_index;
    uint8_t		 	 hs_e[NOISE_PUBLIC_KEY_LEN];
    uint8_t		 	 hs_hash[NOISE_HASH_LEN];
    uint8_t		 	 hs_ck[NOISE_HASH_LEN];
};

struct noise_counter {
    struct rwlock		 c_lock;
    uint64_t		 c_send;
    uint64_t		 c_recv;
    unsigned long		 c_backtrack[COUNTER_NUM];
};

struct noise_keypair {
    SLIST_ENTRY(noise_keypair)	kp_entry;
    int				kp_valid;
    int				kp_is_initiator;
    uint32_t			kp_local_index;
    uint32_t			kp_remote_index;
    uint8_t				kp_send[NOISE_SYMMETRIC_KEY_LEN];
    uint8_t				kp_recv[NOISE_SYMMETRIC_KEY_LEN];
    struct timespec			kp_birthdate; /* nanouptime */
    struct noise_counter		kp_ctr;
};

struct noise_remote {
    uint8_t				 r_public[NOISE_PUBLIC_KEY_LEN];
    struct noise_local		*r_local;
    uint8_t		 		 r_ss[NOISE_PUBLIC_KEY_LEN];

    struct rwlock			 r_handshake_lock;
    struct noise_handshake		 r_handshake;
    uint8_t				 r_psk[NOISE_SYMMETRIC_KEY_LEN];
    uint8_t				 r_timestamp[NOISE_TIMESTAMP_LEN];
    struct timespec			 r_last_init; /* nanouptime */

    struct rwlock			 r_keypair_lock;
    SLIST_HEAD(,noise_keypair)	 r_unused_keypairs;
    struct noise_keypair		*r_next, *r_current, *r_previous;
    struct noise_keypair		 r_keypair[3]; /* 3: next, current, previous. */

};

struct noise_local {
    struct rwlock		l_identity_lock;
    int			l_has_identity;
    uint8_t			l_public[NOISE_PUBLIC_KEY_LEN];
    uint8_t			l_private[NOISE_PUBLIC_KEY_LEN];

    struct noise_upcall {
        void	 *u_arg;
        struct noise_remote *
            (*u_remote_get)(void *, uint8_t[NOISE_PUBLIC_KEY_LEN]);
        uint32_t
            (*u_index_set)(void *, struct noise_remote *);
        void	(*u_index_drop)(void *, uint32_t);
    }			l_upcall;
};

/* Set/Get noise parameters */
void	noise_local_init(struct noise_local *, struct noise_upcall *);
int	noise_local_set_private(struct noise_local *, uint8_t[NOISE_PUBLIC_KEY_LEN]);
int	noise_local_keys(struct noise_local *, uint8_t[NOISE_PUBLIC_KEY_LEN],
        uint8_t[NOISE_PUBLIC_KEY_LEN]);

void	noise_remote_init(struct noise_remote *, uint8_t[NOISE_PUBLIC_KEY_LEN],
        struct noise_local *);
int	noise_remote_set_psk(struct noise_remote *, uint8_t[NOISE_SYMMETRIC_KEY_LEN]);
int	noise_remote_keys(struct noise_remote *, uint8_t[NOISE_PUBLIC_KEY_LEN],
        uint8_t[NOISE_SYMMETRIC_KEY_LEN]);

/* Should be called anytime noise_local_set_private is called */
void	noise_remote_precompute(struct noise_remote *);

/* Cryptographic functions */
int	noise_create_initiation(
        struct noise_remote *,
        uint32_t *s_idx,
        uint8_t ue[NOISE_PUBLIC_KEY_LEN],
        uint8_t es[NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN],
        uint8_t ets[NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN]);

int	noise_consume_initiation(
        struct noise_local *,
        struct noise_remote **,
        uint32_t s_idx,
        uint8_t ue[NOISE_PUBLIC_KEY_LEN],
        uint8_t es[NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN],
        uint8_t ets[NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN]);

int	noise_create_response(
        struct noise_remote *,
        uint32_t *s_idx,
        uint32_t *r_idx,
        uint8_t ue[NOISE_PUBLIC_KEY_LEN],
        uint8_t en[0 + NOISE_AUTHTAG_LEN]);

int	noise_consume_response(
        struct noise_remote *,
        uint32_t s_idx,
        uint32_t r_idx,
        uint8_t ue[NOISE_PUBLIC_KEY_LEN],
        uint8_t en[0 + NOISE_AUTHTAG_LEN]);

int	noise_remote_begin_session(struct noise_remote *);
void	noise_remote_clear(struct noise_remote *);
void	noise_remote_expire_current(struct noise_remote *);

int	noise_remote_ready(struct noise_remote *);

int	noise_remote_encrypt(
        struct noise_remote *,
        uint32_t *r_idx,
        uint64_t *nonce,
        uint8_t *buf,
        size_t buflen);
int	noise_remote_decrypt(
        struct noise_remote *,
        uint32_t r_idx,
        uint64_t nonce,
        uint8_t *buf,
        size_t buflen);

#endif /* __included_wg_noise_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
