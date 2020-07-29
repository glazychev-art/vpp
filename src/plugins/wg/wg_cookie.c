// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <stddef.h>
#include <vlib/vlib.h>

#include <wg/crypto/random.h>
#include <wg/wg_cookie.h>
#include <wg/wg.h>

//enum
//{ COOKIE_KEY_LABEL_LEN = 8 };
//static const u8 mac1_key_label[COOKIE_KEY_LABEL_LEN] = "mac1----";
//static const u8 cookie_key_label[COOKIE_KEY_LABEL_LEN] = "cookie--";

//static void
//precompute_key (u8 key[NOISE_SYMMETRIC_KEY_LEN],
//		const u8 pubkey[NOISE_PUBLIC_KEY_LEN],
//		const u8 label[COOKIE_KEY_LABEL_LEN])
//{
//  blake2s_state_t blake;

//  blake2s_init (&blake, NOISE_SYMMETRIC_KEY_LEN);
//  blake2s_update (&blake, label, COOKIE_KEY_LABEL_LEN);
//  blake2s_update (&blake, pubkey, NOISE_PUBLIC_KEY_LEN);
//  blake2s_final (&blake, key, NOISE_SYMMETRIC_KEY_LEN);
//}

//void
//wg_cookie_init (cookie_t * cookie)
//{
//  clib_memset (cookie, 0, sizeof (*cookie));
//}

//void
//wg_cookie_checker_init (cookie_checker_t * checker, f64 now)
//{
//  checker->secret_birthdate = now;
//  for (int i = 0; i < NOISE_HASH_LEN; ++i)
//    {
//      checker->secret[i] = get_random_u32 ();
//    }
//}

//void
//wg_cookie_checker_precompute_keys (cookie_checker_t * checker,
//                   struct noise_local * local)
//{
//  if (local->l_has_identity)
//    {
//      precompute_key (checker->cookie_encryption_key,
//              local->l_public, cookie_key_label);
//      precompute_key (checker->message_mac1_key,
//              local->l_public, mac1_key_label);
//    }
//  else
//    {
//      memset (checker->cookie_encryption_key, 0, NOISE_SYMMETRIC_KEY_LEN);
//      memset (checker->message_mac1_key, 0, NOISE_SYMMETRIC_KEY_LEN);
//    }
//}

//void
//wg_cookie_checker_precompute_peer_keys (wg_peer_t * peer)
//{
//  precompute_key (peer->latest_cookie.cookie_decryption_key,
//          peer->remote.r_public, cookie_key_label);
//  precompute_key (peer->latest_cookie.message_mac1_key,
//          peer->remote.r_public, mac1_key_label);
//}

//static void
//compute_mac1 (u8 mac1[COOKIE_LEN], const void *message, size_t len,
//          const u8 key[NOISE_SYMMETRIC_KEY_LEN])
//{
//  len = len - sizeof (message_macs_t) + offsetof (message_macs_t, mac1);
//  blake2s (mac1, COOKIE_LEN, message, len, key, NOISE_SYMMETRIC_KEY_LEN);
//}

//static void
//compute_mac2 (u8 mac2[COOKIE_LEN], const void *message, size_t len,
//          const u8 cookie[COOKIE_LEN])
//{
//  len = len - sizeof (message_macs_t) + offsetof (message_macs_t, mac2);
//  blake2s (mac2, COOKIE_LEN, message, len, cookie, COOKIE_LEN);
//}

//void
//wg_cookie_add_mac_to_packet (void *message, size_t len,
//			     wg_peer_t * peer, f64 now)
//{
//  message_macs_t *macs = (message_macs_t *)
//    ((u8 *) message + len - sizeof (*macs));

//  compute_mac1 (macs->mac1, message, len,
//		peer->latest_cookie.message_mac1_key);

//  clib_memcpy (peer->latest_cookie.last_mac1_sent, macs->mac1, COOKIE_LEN);
//  peer->latest_cookie.have_sent_mac1 = true;

//  if (peer->latest_cookie.is_valid &&
//      !wg_birthdate_has_expired (peer->latest_cookie.birthdate,
//				 COOKIE_SECRET_MAX_AGE -
//				 COOKIE_SECRET_LATENCY, now))
//    {
//      compute_mac2 (macs->mac2, message, len, peer->latest_cookie.cookie);
//    }
//  else
//    {
//      clib_memset (macs->mac2, 0, COOKIE_LEN);
//    }
//}

//void
//wg_cookie_message_consume (vlib_main_t * vm, const wg_index_table_t * table,
//			   wg_peer_t * peer_pool,
//			   message_handshake_cookie_t * src)
//{
//  wg_peer_t *peer = NULL;
//  u8 cookie[COOKIE_LEN];
//  bool ret;

//  u32 *entry =
//    wg_index_table_lookup (table, src->receiver_index);
//  if (entry) {
//    peer = pool_elt_at_index (peer_pool, *entry);
//  }
//  if (!peer)
//    return;

//  if (!peer->latest_cookie.have_sent_mac1)
//    return;

//  ret =
//    xchacha20poly1305_decrypt (cookie, src->encrypted_cookie,
//			       sizeof (src->encrypted_cookie),
//			       peer->latest_cookie.last_mac1_sent, COOKIE_LEN,
//			       src->nonce,
//			       peer->latest_cookie.cookie_decryption_key);

//  if (ret)
//    {
//      memcpy (peer->latest_cookie.cookie, cookie, COOKIE_LEN);
//      peer->latest_cookie.birthdate = vlib_time_now (vm);
//      peer->latest_cookie.is_valid = true;
//      peer->latest_cookie.have_sent_mac1 = false;
//    }
//}

//static void
//make_cookie (vlib_main_t * vm, u8 cookie[COOKIE_LEN], ip4_address_t ip4,
//	     u16 udp_src, cookie_checker_t * checker)
//{
//  blake2s_state_t state;
//  f64 now = vlib_time_now (vm);
//  if (wg_birthdate_has_expired (checker->secret_birthdate,
//				COOKIE_SECRET_MAX_AGE, now))
//    {
//      checker->secret_birthdate = now;
//      for (int i = 0; i < NOISE_HASH_LEN; ++i)
//	{
//	  checker->secret[i] = get_random_u32 ();
//	}
//    }

//  blake2s_init_key (&state, COOKIE_LEN, checker->secret, NOISE_HASH_LEN);
//  blake2s_update (&state, ip4.as_u8, sizeof (ip4_address_t));	//TODO: IP6

//  blake2s_update (&state, (u8 *) & udp_src, sizeof (u16));
//  blake2s_final (&state, cookie, COOKIE_LEN);
//}


//enum cookie_mac_state
//wg_cookie_validate_packet (vlib_main_t * vm, cookie_checker_t * checker,
//			   void *message, size_t len, ip4_address_t ip4,
//			   u16 udp_src, bool check_cookie)
//{
//  enum cookie_mac_state ret;
//  u8 computed_mac[COOKIE_LEN];
//  u8 cookie[COOKIE_LEN];

//  message_macs_t *macs = (message_macs_t *)
//    ((u8 *) message + len - sizeof (*macs));

//  ret = INVALID_MAC;
//  compute_mac1 (computed_mac, message, len, checker->message_mac1_key);
//  if (memcmp (computed_mac, macs->mac1, COOKIE_LEN))
//    return ret;

//  ret = VALID_MAC_BUT_NO_COOKIE;

//  if (!check_cookie)
//    return ret;

//  make_cookie (vm, cookie, ip4, udp_src, checker);

//  compute_mac2 (computed_mac, message, len, cookie);
//  if (memcmp (computed_mac, macs->mac2, COOKIE_LEN))
//    return ret;

//  ret = VALID_MAC_WITH_COOKIE;
//  return ret;
//}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////_______NEW__REALIZATION_______////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static void	cookie_precompute_key(uint8_t *,
            const uint8_t[COOKIE_INPUT_SIZE], const char *);
static void	cookie_macs_mac1(message_macs_t *, const void *, size_t,
            const uint8_t[COOKIE_KEY_SIZE]);
static void	cookie_macs_mac2(message_macs_t *, const void *, size_t,
            const uint8_t[COOKIE_COOKIE_SIZE]);
static void	cookie_checker_make_cookie(vlib_main_t * vm, struct cookie_checker *,
            uint8_t[COOKIE_COOKIE_SIZE],  ip4_address_t ip4, u16 udp_port);
//static int	ratelimit_init(struct ratelimit *, struct pool *pool);
//static void	ratelimit_deinit(struct ratelimit *);
//static void	ratelimit_gc(struct ratelimit *, int);
//static int	ratelimit_allow(struct ratelimit *, struct sockaddr *);

/* Public Functions */
void
cookie_maker_init(struct cookie_maker *cp, uint8_t key[COOKIE_INPUT_SIZE])
{
    clib_memset (cp, 0, sizeof(*cp));
    cookie_precompute_key(cp->cp_mac1_key, key, COOKIE_MAC1_KEY_LABEL);
    cookie_precompute_key(cp->cp_cookie_key, key, COOKIE_COOKIE_KEY_LABEL);
}

//int
//cookie_checker_init(struct cookie_checker *cc, struct pool *pool)
//{
//    int res;
//    bzero(cc, sizeof(*cc));

//    if ((res = ratelimit_init(&cc->cc_ratelimit_v4, pool)) != 0)
//        return res;
//#ifdef INET6
//    if ((res = ratelimit_init(&cc->cc_ratelimit_v6, pool)) != 0) {
//        ratelimit_deinit(&cc->cc_ratelimit_v4);
//        return res;
//    }
//#endif
//    return 0;
//}

void
cookie_checker_update(struct cookie_checker *cc,
    uint8_t key[COOKIE_INPUT_SIZE])
{
    if (key) {
        cookie_precompute_key(cc->cc_mac1_key, key, COOKIE_MAC1_KEY_LABEL);
        cookie_precompute_key(cc->cc_cookie_key, key, COOKIE_COOKIE_KEY_LABEL);
    } else {
        clib_memset (cc->cc_mac1_key, 0, sizeof(cc->cc_mac1_key));
        clib_memset (cc->cc_cookie_key, 0, sizeof(cc->cc_cookie_key));
    }
}

//void
//cookie_checker_deinit(struct cookie_checker *cc)
//{
//    ratelimit_deinit(&cc->cc_ratelimit_v4);
//#ifdef INET6
//    ratelimit_deinit(&cc->cc_ratelimit_v6);
//#endif
//}

//void
//cookie_checker_create_payload(struct cookie_checker *cc,
//    struct cookie_macs *cm, uint8_t nonce[COOKIE_NONCE_SIZE],
//    uint8_t ecookie[COOKIE_ENCRYPTED_SIZE], struct sockaddr *sa)
//{
//    uint8_t cookie[COOKIE_COOKIE_SIZE];

//    cookie_checker_make_cookie(cc, cookie, sa);
//    arc4random_buf(nonce, COOKIE_NONCE_SIZE);

//    rw_enter_read(&cc->cc_key_lock);
//    xchacha20poly1305_encrypt(ecookie, cookie, COOKIE_COOKIE_SIZE,
//        cm->mac1, COOKIE_MAC_SIZE, nonce, cc->cc_cookie_key);
//    rw_exit_read(&cc->cc_key_lock);

//    explicit_bzero(cookie, sizeof(cookie));
//}

bool
cookie_maker_consume_payload(vlib_main_t * vm, struct cookie_maker *cp,
    uint8_t nonce[COOKIE_NONCE_SIZE], uint8_t ecookie[COOKIE_ENCRYPTED_SIZE])
{
    uint8_t cookie[COOKIE_COOKIE_SIZE];

    if (cp->cp_mac1_valid == 0) {
        return false;
    }

    if (!xchacha20poly1305_decrypt(cookie, ecookie, COOKIE_ENCRYPTED_SIZE,
        cp->cp_mac1_last, COOKIE_MAC_SIZE, nonce, cp->cp_cookie_key)) {
        return false;
    }

    clib_memcpy(cp->cp_cookie, cookie, COOKIE_COOKIE_SIZE);
    cp->cp_birthdate = vlib_time_now(vm);
    cp->cp_mac1_valid = 0;

    return true;
}

void
cookie_maker_mac(struct cookie_maker *cp, message_macs_t *cm, void *buf,
        size_t len)
{
    len = len - sizeof (message_macs_t);
    cookie_macs_mac1(cm, buf, len, cp->cp_mac1_key);

    clib_memcpy (cp->cp_mac1_last, cm->mac1, COOKIE_MAC_SIZE);
    cp->cp_mac1_valid = 1;

    if (!wg_birthdate_has_expired(cp->cp_birthdate,
        COOKIE_SECRET_MAX_AGE - COOKIE_SECRET_LATENCY))
        cookie_macs_mac2(cm, buf, len, cp->cp_cookie);
    else
        clib_memset (cm->mac2, 0, COOKIE_MAC_SIZE);
}

enum cookie_mac_state
cookie_checker_validate_macs(vlib_main_t * vm, struct cookie_checker *cc, message_macs_t *cm,
        void *buf, size_t len, bool busy, ip4_address_t ip4, u16 udp_port)
{
    message_macs_t our_cm;
    uint8_t cookie[COOKIE_COOKIE_SIZE];

    len = len - sizeof (message_macs_t);
    cookie_macs_mac1(&our_cm, buf, len, cc->cc_mac1_key);

    /* If mac1 is invald, we want to drop the packet */
    if (clib_memcmp(our_cm.mac1, cm->mac1, COOKIE_MAC_SIZE) != 0)
        return INVALID_MAC;

    if (!busy)
        return VALID_MAC_BUT_NO_COOKIE;

    cookie_checker_make_cookie(vm, cc, cookie, ip4, udp_port);
    cookie_macs_mac2(&our_cm, buf, len, cookie);

    /* If the mac2 is invalid, we want to send a cookie response */
    if (clib_memcmp(our_cm.mac2, cm->mac2, COOKIE_MAC_SIZE) != 0)
        return VALID_MAC_BUT_NO_COOKIE;

    /* If the mac2 is valid, we may want rate limit the peer.
     * ratelimit_allow will return either 0 or ECONNREFUSED,
     * implying there is no ratelimiting, or we should ratelimit
     * (refuse) respectively. */
//    if (sa->sa_family == AF_INET)
//        return ratelimit_allow(&cc->cc_ratelimit_v4, sa);
//    else
//        return EAFNOSUPPORT;

    return VALID_MAC_WITH_COOKIE;
}

/* Private functions */
static void
cookie_precompute_key(uint8_t *key, const uint8_t input[COOKIE_INPUT_SIZE],
    const char *label)
{
    struct blake2s_state blake;

    blake2s_init(&blake, COOKIE_KEY_SIZE);
    blake2s_update(&blake, label, strlen(label));
    blake2s_update(&blake, input, COOKIE_INPUT_SIZE);
    blake2s_final(&blake, key, COOKIE_KEY_SIZE);
}

static void
cookie_macs_mac1(message_macs_t *cm, const void *buf, size_t len,
    const uint8_t key[COOKIE_KEY_SIZE])
{
    struct blake2s_state state;
    blake2s_init_key(&state, COOKIE_MAC_SIZE, key, COOKIE_KEY_SIZE);
    blake2s_update(&state, buf, len);
    blake2s_final(&state, cm->mac1, COOKIE_MAC_SIZE);
}

static void
cookie_macs_mac2(message_macs_t *cm, const void *buf, size_t len,
        const uint8_t key[COOKIE_COOKIE_SIZE])
{
    struct blake2s_state state;
    blake2s_init_key(&state, COOKIE_MAC_SIZE, key, COOKIE_COOKIE_SIZE);
    blake2s_update(&state, buf, len);
    blake2s_update(&state, cm->mac1, COOKIE_MAC_SIZE);
    blake2s_final(&state, cm->mac2, COOKIE_MAC_SIZE);
}

static void
cookie_checker_make_cookie(vlib_main_t * vm, struct cookie_checker *cc,
        uint8_t cookie[COOKIE_COOKIE_SIZE], ip4_address_t ip4, u16 udp_port)
{
    blake2s_state_t state;

    if (wg_birthdate_has_expired(cc->cc_secret_birthdate,
        COOKIE_SECRET_MAX_AGE)) {

        cc->cc_secret_birthdate = vlib_time_now (vm);
        for (int i = 0; i < COOKIE_SECRET_SIZE; ++i)
      {
        cc->cc_secret[i] = get_random_u32 ();
      }
    }
    blake2s_init_key(&state, COOKIE_COOKIE_SIZE, cc->cc_secret,
        COOKIE_SECRET_SIZE);

    blake2s_update(&state, ip4.as_u8, sizeof (ip4_address_t));	//TODO: IP6
    blake2s_update (&state, (u8 *) &udp_port, sizeof (u16));
    blake2s_final (&state, cookie, COOKIE_COOKIE_SIZE);

}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
