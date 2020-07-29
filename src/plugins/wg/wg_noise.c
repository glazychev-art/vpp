// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <openssl/hmac.h>
#include <wg/wg.h>

/* This implements Noise_IKpsk2:
 *
 * <- s
 * ******
 * -> e, es, s, ss, {t}
 * <- e, ee, se, psk, {}
 */

//static const u8 handshake_name[37] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
//static const u8 identifier_name[34] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
//static u8 handshake_init_hash[NOISE_HASH_LEN];
//static u8 handshake_init_chaining_key[NOISE_HASH_LEN];

//void
//wg_noise_handshake_init (wg_peer_t * peer,
//			 noise_static_identity_t * static_identity,
//			 const u8 peer_public_key[NOISE_PUBLIC_KEY_LEN],
//			 const u8 peer_preshared_key[NOISE_SYMMETRIC_KEY_LEN])
//{
//  noise_handshake_t *handshake = &peer->handshake;
//  memset (handshake, 0, sizeof (*handshake));
//  handshake->peer = peer;
//  memcpy (handshake->remote_static, peer_public_key, NOISE_PUBLIC_KEY_LEN);
//  if (peer_preshared_key)
//    memcpy (handshake->preshared_key, peer_preshared_key,
//	    NOISE_SYMMETRIC_KEY_LEN);
//  handshake->static_identity = static_identity;
//  handshake->state = HANDSHAKE_ZEROED;
//  wg_noise_precompute_static_static (handshake);
//}

//static void
//handshake_zero (noise_handshake_t * handshake)
//{
//  clib_memset (&handshake->ephemeral_private, 0, NOISE_PUBLIC_KEY_LEN);
//  clib_memset (&handshake->remote_ephemeral, 0, NOISE_PUBLIC_KEY_LEN);
//  clib_memset (&handshake->hash, 0, NOISE_HASH_LEN);
//  clib_memset (&handshake->chaining_key, 0, NOISE_HASH_LEN);
//  handshake->remote_index = 0;
//  handshake->local_index = 0;
//  handshake->state = HANDSHAKE_ZEROED;
//}

//void
//wg_noise_handshake_clear (noise_handshake_t * handshake)
//{
//  wg_main_t *wmp = &wg_main;

//  wg_index_table_del (&wmp->index_table, handshake->local_index);
//  handshake_zero (handshake);
//}

//static void
//del_keypair (wg_index_table_t * table, noise_keypair_t ** keypair)
//{
//  if (*keypair)
//    {
//      wg_index_table_del (table, (*keypair)->local_index);
//      clib_mem_free (*keypair);
//      *keypair = NULL;
//    }
//}

//void
//wg_noise_keypairs_clear (noise_keypairs_t * keypairs)
//{
//  wg_main_t *wmp = &wg_main;
//  del_keypair (&wmp->index_table, &keypairs->next_keypair);
//  del_keypair (&wmp->index_table, &keypairs->previous_keypair);
//  del_keypair (&wmp->index_table, &keypairs->current_keypair);
//}

//bool
//wg_noise_received_with_keypair (wg_index_table_t * table,
//				noise_keypairs_t * keypairs,
//				noise_keypair_t * new_keypair)
//{
//  noise_keypair_t *old_keypair;

//  if (keypairs->next_keypair != new_keypair)
//    {
//      return false;
//    }

//  old_keypair = keypairs->previous_keypair;
//  keypairs->previous_keypair = keypairs->current_keypair;
//  keypairs->current_keypair = keypairs->next_keypair;
//  keypairs->next_keypair = NULL;

//  del_keypair (table, &old_keypair);

//  return true;
//}

//void
//wg_noise_set_static_identity_private_key (noise_static_identity_t *static_identity,
//                      const u8 private_key[NOISE_PUBLIC_KEY_LEN])
//{
//  clib_memcpy (static_identity->static_private, private_key,
//	       NOISE_PUBLIC_KEY_LEN);
//  curve25519_clamp_secret (static_identity->static_private);
//  static_identity->has_identity =
//    curve25519_gen_public (static_identity->static_public, private_key);
//}

//void
//wg_noise_precompute_static_static (noise_handshake_t * handshake)
//{
//  if (!handshake->static_identity->has_identity ||
//      !curve25519_gen_shared (handshake->precomputed_static_static,
//			      handshake->static_identity->static_private,
//			      handshake->remote_static))
//    memset (handshake->precomputed_static_static, 0, NOISE_PUBLIC_KEY_LEN);
//}

///* This is Hugo Krawczyk's HKDF:
// *  - https://eprint.iacr.org/2010/264.pdf
// *  - https://tools.ietf.org/html/rfc5869
// */
//static void
//kdf (u8 * first_dst, u8 * second_dst, u8 * third_dst, const u8 * data,
//     size_t first_len, size_t second_len, size_t third_len,
//     size_t data_len, const u8 chaining_key[NOISE_HASH_LEN])
//{
//  u8 output[BLAKE2S_HASHSIZE + 1];
//  u8 secret[BLAKE2S_HASHSIZE];

//  /* Extract entropy from data into secret */
//  u32 l = 0;
//  HMAC (EVP_blake2s256 (), chaining_key, NOISE_HASH_LEN, data, data_len,
//	secret, &l);
//  ASSERT (l == BLAKE2S_HASHSIZE);

//  if (!first_dst || !first_len)
//    goto out;

//  /* Expand first key: key = secret, data = 0x1 */
//  output[0] = 1;
//  HMAC (EVP_blake2s256 (), secret, BLAKE2S_HASHSIZE, output, 1, output, &l);
//  ASSERT (l == BLAKE2S_HASHSIZE);

//  clib_memcpy (first_dst, output, first_len);

//  if (!second_dst || !second_len)
//    goto out;

//  /* Expand second key: key = secret, data = first-key || 0x2 */
//  output[BLAKE2S_HASHSIZE] = 2;
//  HMAC (EVP_blake2s256 (), secret, BLAKE2S_HASHSIZE, output,
//	BLAKE2S_HASHSIZE + 1, output, &l);
//  ASSERT (l == BLAKE2S_HASHSIZE);

//  clib_memcpy (second_dst, output, second_len);

//  if (!third_dst || !third_len)
//    goto out;

//  /* Expand third key: key = secret, data = second-key || 0x3 */
//  output[BLAKE2S_HASHSIZE] = 3;
//  HMAC (EVP_blake2s256 (), secret, BLAKE2S_HASHSIZE, output,
//	BLAKE2S_HASHSIZE + 1, output, &l);
//  ASSERT (l == BLAKE2S_HASHSIZE);

//  clib_memcpy (third_dst, output, third_len);

//out:
//  /* Clear sensitive data from stack */
//  secure_zero_memory (secret, BLAKE2S_HASHSIZE);
//  secure_zero_memory (output, BLAKE2S_HASHSIZE + 1);
//}

//static void
//symmetric_key_init (noise_symmetric_key_t * key, f64 now)
//{
//  key->counter.counter = 0;
//  clib_memset (key->counter.receive.backtrack, 0,
//	       sizeof (key->counter.receive.backtrack));
//  key->birthdate = now;
//  key->is_valid = true;
//}

//static void
//derive_keys (noise_symmetric_key_t * first_dst,
//	     noise_symmetric_key_t * second_dst,
//	     const u8 chaining_key[NOISE_HASH_LEN], f64 now)
//{
//  kdf (first_dst->key, second_dst->key, NULL, NULL,
//       NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, 0, chaining_key);
//  symmetric_key_init (first_dst, now);
//  symmetric_key_init (second_dst, now);
//}

//static bool
//mix_dh (u8 chaining_key[NOISE_HASH_LEN],
//	u8 key[NOISE_SYMMETRIC_KEY_LEN],
//	const u8 private[NOISE_PUBLIC_KEY_LEN],
//	const u8 public[NOISE_PUBLIC_KEY_LEN])
//{
//  u8 dh_calculation[NOISE_PUBLIC_KEY_LEN];

//  if (!curve25519_gen_shared (dh_calculation, private, public))
//    return false;
//  kdf (chaining_key, key, NULL, dh_calculation, NOISE_HASH_LEN,
//       NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN, chaining_key);
//  secure_zero_memory (dh_calculation, NOISE_PUBLIC_KEY_LEN);
//  return true;
//}

//static bool
//mix_precomputed_dh (u8 chaining_key[NOISE_HASH_LEN],
//		    u8 key[NOISE_SYMMETRIC_KEY_LEN],
//		    const u8 precomputed[NOISE_PUBLIC_KEY_LEN])
//{
//  static u8 zero_point[NOISE_PUBLIC_KEY_LEN];
//  if (!memcmp (precomputed, zero_point, NOISE_PUBLIC_KEY_LEN))
//    return false;
//  kdf (chaining_key, key, NULL, precomputed, NOISE_HASH_LEN,
//       NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN, chaining_key);
//  return true;
//}

//static void
//mix_hash (u8 hash[NOISE_HASH_LEN], const u8 * src, size_t src_len)
//{
//  blake2s_state_t blake;

//  blake2s_init (&blake, NOISE_HASH_LEN);
//  blake2s_update (&blake, hash, NOISE_HASH_LEN);
//  blake2s_update (&blake, src, src_len);
//  blake2s_final (&blake, hash, NOISE_HASH_LEN);
//}

//static void
//mix_psk (u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN],
//	 u8 key[NOISE_SYMMETRIC_KEY_LEN],
//	 const u8 psk[NOISE_SYMMETRIC_KEY_LEN])
//{
//  u8 temp_hash[NOISE_HASH_LEN];

//  kdf (chaining_key, temp_hash, key, psk, NOISE_HASH_LEN, NOISE_HASH_LEN,
//       NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, chaining_key);
//  mix_hash (hash, temp_hash, NOISE_HASH_LEN);
//  secure_zero_memory (temp_hash, NOISE_HASH_LEN);
//}

//static void
//handshake_init (u8 chaining_key[NOISE_HASH_LEN],
//		u8 hash[NOISE_HASH_LEN],
//		const u8 remote_static[NOISE_PUBLIC_KEY_LEN])
//{
//  clib_memcpy (hash, handshake_init_hash, NOISE_HASH_LEN);
//  clib_memcpy (chaining_key, handshake_init_chaining_key, NOISE_HASH_LEN);
//  mix_hash (hash, remote_static, NOISE_PUBLIC_KEY_LEN);
//}

//static void
//message_encrypt (u8 * dst_ciphertext, const u8 * src_plaintext,
//		 size_t src_len, u8 key[NOISE_SYMMETRIC_KEY_LEN],
//		 u8 hash[NOISE_HASH_LEN])
//{
//  chacha20poly1305_encrypt (dst_ciphertext, src_plaintext, src_len, hash,
//			    NOISE_HASH_LEN,
//			    0 /* Always zero for Noise_IK */ , key);
//  mix_hash (hash, dst_ciphertext, noise_encrypted_len (src_len));
//}

//static bool
//message_decrypt (u8 * dst_plaintext, const u8 * src_ciphertext,
//		 size_t src_len, u8 key[NOISE_SYMMETRIC_KEY_LEN],
//		 u8 hash[NOISE_HASH_LEN])
//{
//  if (!chacha20poly1305_decrypt (dst_plaintext, src_ciphertext, src_len,
//				 hash, NOISE_HASH_LEN,
//				 0 /* Always zero for Noise_IK */ , key))
//    return false;
//  mix_hash (hash, src_ciphertext, src_len);
//  return true;
//}

//static void
//message_ephemeral (u8 ephemeral_dst[NOISE_PUBLIC_KEY_LEN],
//		   const u8 ephemeral_src[NOISE_PUBLIC_KEY_LEN],
//		   u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN])
//{
//  if (ephemeral_dst != ephemeral_src)
//    memcpy (ephemeral_dst, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
//  mix_hash (hash, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
//  kdf (chaining_key, NULL, NULL, ephemeral_src, NOISE_HASH_LEN, 0, 0,
//       NOISE_PUBLIC_KEY_LEN, chaining_key);
//}

//static void
//tai64n_now (vlib_main_t * vm, u8 output[NOISE_TIMESTAMP_LEN])
//{
//  //TODO: check this method.
//  u64 timeNow = vlib_time_now (vm);
//  if (!CLIB_ARCH_IS_BIG_ENDIAN)
//    {
//      *(u64 *) output = clib_byte_swap_u64 (0x400000000000000aULL + timeNow);
//    }
//  else
//    {
//      *(u64 *) output = (0x400000000000000aULL + timeNow);
//    }
//}

//bool
//wg_noise_handshake_create_initiation (vlib_main_t * vm,
//				      message_handshake_initiation_t * dst,
//				      wg_peer_t * peer,
//				      wg_index_table_t * index_table,
//				      wg_peer_t * peer_pool)
//{
//  u8 timestamp[NOISE_TIMESTAMP_LEN];
//  u8 key[NOISE_SYMMETRIC_KEY_LEN];
//  bool ret = false;

//  noise_handshake_t *handshake = &peer->handshake;

//  if (!handshake->static_identity->has_identity)
//    goto out;

//  dst->header.type = MESSAGE_HANDSHAKE_INITIATION;

//  handshake_init (handshake->chaining_key, handshake->hash,
//		  handshake->remote_static);

//  /* e */
//  curve25519_gen_secret (handshake->ephemeral_private);
//  if (!curve25519_gen_public (dst->unencrypted_ephemeral,
//			      handshake->ephemeral_private))
//    goto out;
//  message_ephemeral (dst->unencrypted_ephemeral,
//		     dst->unencrypted_ephemeral, handshake->chaining_key,
//		     handshake->hash);

//  /* es */
//  if (!mix_dh (handshake->chaining_key, key, handshake->ephemeral_private,
//	       handshake->remote_static))
//    goto out;

//  /* s */
//  message_encrypt (dst->encrypted_static,
//		   handshake->static_identity->static_public,
//		   NOISE_PUBLIC_KEY_LEN, key, handshake->hash);

//  /* ss */
//  if (!mix_precomputed_dh (handshake->chaining_key, key,
//			   handshake->precomputed_static_static))
//    goto out;

//  /* {t} */
//  tai64n_now (vm, timestamp);
//  message_encrypt (dst->encrypted_timestamp, timestamp,
//		   NOISE_TIMESTAMP_LEN, key, handshake->hash);

//  dst->sender_index = wg_index_table_add (index_table, peer - peer_pool);
//  handshake->local_index = dst->sender_index;

//  handshake->state = HANDSHAKE_CREATED_INITIATION;
//  ret = true;

//out:
//  secure_zero_memory (key, NOISE_SYMMETRIC_KEY_LEN);
//  return ret;
//}

//wg_peer_t *
//wg_noise_handshake_consume_response (message_handshake_response_t * src,
//				     noise_static_identity_t *
//				     static_identify,
//				     wg_index_table_t * index_table,
//				     wg_peer_t * peer_pool)
//{
//  enum noise_handshake_state state = HANDSHAKE_ZEROED;
//  wg_peer_t *peer = NULL, *ret_peer = NULL;
//  noise_handshake_t *handshake;
//  u8 key[NOISE_SYMMETRIC_KEY_LEN];
//  u8 hash[NOISE_HASH_LEN];
//  u8 chaining_key[NOISE_HASH_LEN];
//  u8 e[NOISE_PUBLIC_KEY_LEN];
//  u8 ephemeral_private[NOISE_PUBLIC_KEY_LEN];
//  u8 static_private[NOISE_PUBLIC_KEY_LEN];

//  if (!static_identify->has_identity)
//    goto out;

//  index_table_entry_t *entry =
//    wg_index_table_lookup (index_table, src->receiver_index);
//  if (entry)
//    {
//      peer = pool_elt_at_index (peer_pool, entry->peer_pool_idx);
//      handshake = &peer->handshake;
//      if (!handshake || !peer)
//	goto out;
//    }
//  else
//    {
//      goto out;
//    }

//  state = handshake->state;
//  clib_memcpy (hash, handshake->hash, NOISE_HASH_LEN);
//  clib_memcpy (chaining_key, handshake->chaining_key, NOISE_HASH_LEN);
//  clib_memcpy (ephemeral_private, handshake->ephemeral_private,
//	       NOISE_PUBLIC_KEY_LEN);

//  if (state != HANDSHAKE_CREATED_INITIATION)
//    goto out;

//  /* e */
//  message_ephemeral (e, src->unencrypted_ephemeral, chaining_key, hash);

//  /* ee */
//  if (!mix_dh (chaining_key, NULL, ephemeral_private, e))
//    goto out;

//  /* se */
//  if (!mix_dh (chaining_key, NULL, static_identify->static_private, e))
//    goto out;

//  /* psk */
//  mix_psk (chaining_key, hash, key, handshake->preshared_key);

//  /* {} */
//  if (!message_decrypt (NULL, src->encrypted_nothing,
//			sizeof (src->encrypted_nothing), key, hash))
//    goto out;

//  if (handshake->state != state)
//    {
//      goto out;
//    }
//  clib_memcpy (handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
//  clib_memcpy (handshake->hash, hash, NOISE_HASH_LEN);
//  clib_memcpy (handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
//  handshake->remote_index = src->sender_index;
//  handshake->state = HANDSHAKE_CONSUMED_RESPONSE;
//  ret_peer = peer;

//out:
//  secure_zero_memory (key, NOISE_SYMMETRIC_KEY_LEN);
//  secure_zero_memory (hash, NOISE_HASH_LEN);
//  secure_zero_memory (chaining_key, NOISE_HASH_LEN);
//  secure_zero_memory (ephemeral_private, NOISE_PUBLIC_KEY_LEN);
//  secure_zero_memory (static_private, NOISE_PUBLIC_KEY_LEN);
//  return ret_peer;
//}

//bool
//wg_noise_handshake_create_response (message_handshake_response_t * dst,
//				    wg_peer_t * peer,
//				    wg_index_table_t * index_table,
//				    wg_peer_t * peer_pool)
//{
//  u8 key[NOISE_SYMMETRIC_KEY_LEN];
//  bool ret = false;

//  noise_handshake_t *handshake = &peer->handshake;

//  if (handshake->state != HANDSHAKE_CONSUMED_INITIATION)
//    goto out;

//  dst->header.type = MESSAGE_HANDSHAKE_RESPONSE;
//  dst->receiver_index = handshake->remote_index;

//  /* e */
//  curve25519_gen_secret (handshake->ephemeral_private);
//  if (!curve25519_gen_public (dst->unencrypted_ephemeral,
//			      handshake->ephemeral_private))
//    goto out;
//  message_ephemeral (dst->unencrypted_ephemeral,
//		     dst->unencrypted_ephemeral, handshake->chaining_key,
//		     handshake->hash);

//  /* ee */
//  if (!mix_dh (handshake->chaining_key, NULL, handshake->ephemeral_private,
//	       handshake->remote_ephemeral))
//    goto out;

//  /* se */
//  if (!mix_dh (handshake->chaining_key, NULL, handshake->ephemeral_private,
//	       handshake->remote_static))
//    goto out;

//  /* psk */
//  mix_psk (handshake->chaining_key, handshake->hash, key,
//	   handshake->preshared_key);

//  /* {} */
//  message_encrypt (dst->encrypted_nothing, NULL, 0, key, handshake->hash);

//  dst->sender_index = wg_index_table_add (index_table, peer - peer_pool);
//  handshake->local_index = dst->sender_index;

//  handshake->state = HANDSHAKE_CREATED_RESPONSE;
//  ret = true;

//out:
//  secure_zero_memory (key, NOISE_SYMMETRIC_KEY_LEN);
//  return ret;
//}

//static void
//add_new_keypair (wg_index_table_t * table, noise_keypairs_t * keypairs,
//		 noise_keypair_t * new_keypair)
//{
//  noise_keypair_t *next_keypair, *current_keypair, *previous_keypair;

//  next_keypair = keypairs->next_keypair;
//  current_keypair = keypairs->current_keypair;
//  previous_keypair = keypairs->previous_keypair;

//  if (new_keypair->i_am_the_initiator)
//    {
//      if (next_keypair)
//	{
//	  keypairs->next_keypair = NULL;
//	  keypairs->previous_keypair = next_keypair;
//	  del_keypair (table, &current_keypair);
//	}
//      else
//	{
//	  keypairs->previous_keypair = current_keypair;
//	}

//      del_keypair (table, &previous_keypair);
//      keypairs->current_keypair = new_keypair;
//    }
//  else
//    {
//      keypairs->next_keypair = new_keypair;
//      del_keypair (table, &next_keypair);
//      keypairs->previous_keypair = NULL;
//      del_keypair (table, &previous_keypair);
//    }
//}

//static noise_keypair_t *
//keypair_create (wg_peer_t * peer)
//{
//  noise_keypair_t *keypair = clib_mem_alloc (sizeof (*keypair));
//  return keypair;
//}



//bool
//wg_noise_handshake_begin_session (vlib_main_t * vm,
//				  noise_handshake_t * handshake,
//				  noise_keypairs_t * keypairs)
//{
//  f64 now;
//  noise_keypair_t *new_keypair;
//  bool ret = false;

//  if (handshake->state != HANDSHAKE_CREATED_RESPONSE &&
//      handshake->state != HANDSHAKE_CONSUMED_RESPONSE)
//    goto out;

//  new_keypair = keypair_create (handshake->peer);
//  if (!new_keypair)
//    goto out;

//  new_keypair->i_am_the_initiator = handshake->state ==
//    HANDSHAKE_CONSUMED_RESPONSE;
//  new_keypair->remote_index = handshake->remote_index;
//  new_keypair->local_index = handshake->local_index;

//  now = vlib_time_now (vm);
//  if (new_keypair->i_am_the_initiator)
//    derive_keys (&new_keypair->sending, &new_keypair->receiving,
//		 handshake->chaining_key, now);
//  else
//    derive_keys (&new_keypair->receiving, &new_keypair->sending,
//		 handshake->chaining_key, now);

//  wg_main_t *wmp = &wg_main;
//  wg_index_table_add_keypair (&wmp->index_table, handshake->local_index,
//			      new_keypair);
//  handshake_zero (handshake);

//  if (!handshake->peer->is_dead)
//    {
//      add_new_keypair (&wmp->index_table, keypairs, new_keypair);
//      ret = true;
//    }

//out:
//  return ret;
//}

//wg_peer_t *
//wg_noise_handshake_consume_initiation (message_handshake_initiation_t * src,
//				       noise_static_identity_t *
//				       static_identify, wg_peer_t * peer_pool)
//{
//  wg_peer_t *peer = NULL, *ret_peer = NULL;
//  noise_handshake_t *handshake;
//  u8 key[NOISE_SYMMETRIC_KEY_LEN];
//  u8 chaining_key[NOISE_HASH_LEN];
//  u8 hash[NOISE_HASH_LEN];
//  u8 s[NOISE_PUBLIC_KEY_LEN];
//  u8 e[NOISE_PUBLIC_KEY_LEN];
//  u8 t[NOISE_TIMESTAMP_LEN];

//  if (!static_identify->has_identity)
//    goto out;

//  handshake_init (chaining_key, hash, static_identify->static_public);

//  /* e */
//  message_ephemeral (e, src->unencrypted_ephemeral, chaining_key, hash);

//  /* es */
//  if (!mix_dh (chaining_key, key, static_identify->static_private, e))
//    goto out;

//  /* s */
//  if (!message_decrypt (s, src->encrypted_static,
//			sizeof (src->encrypted_static), key, hash))
//    goto out;

//  wg_peer_t *peer_iter;
//  pool_foreach (peer_iter, peer_pool, (
//					{
//					if (!memcmp
//					    (peer_iter->
//					     handshake.remote_static, s,
//					     NOISE_PUBLIC_KEY_LEN))
//					{
//					peer = peer_iter; break;}
//					}
//		));
//  if (!peer)
//    {
//      return NULL;
//    }

//  handshake = &peer->handshake;

//  /* ss */
//  if (!mix_precomputed_dh (chaining_key, key,
//			   handshake->precomputed_static_static))
//    goto out;

//  /* {t} */
//  if (!message_decrypt (t, src->encrypted_timestamp,
//			sizeof (src->encrypted_timestamp), key, hash))
//    goto out;

//  clib_memcpy (handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
//  if (memcmp (t, handshake->latest_timestamp, NOISE_TIMESTAMP_LEN) > 0)
//    clib_memcpy (handshake->latest_timestamp, t, NOISE_TIMESTAMP_LEN);
//  clib_memcpy (handshake->hash, hash, NOISE_HASH_LEN);
//  clib_memcpy (handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
//  handshake->remote_index = src->sender_index;
//  handshake->state = HANDSHAKE_CONSUMED_INITIATION;
//  ret_peer = peer;

//out:
//  secure_zero_memory (key, NOISE_SYMMETRIC_KEY_LEN);
//  secure_zero_memory (hash, NOISE_HASH_LEN);
//  secure_zero_memory (chaining_key, NOISE_HASH_LEN);
//  return ret_peer;
//}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////_______NEW__REALIZATION_______////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


/* Private functions */
static struct noise_keypair *
        noise_remote_keypair_allocate(struct noise_remote *);
static void
        noise_remote_keypair_free(struct noise_remote *,
            struct noise_keypair **);
static uint32_t	noise_remote_handshake_index_get(struct noise_remote *);
static void	noise_remote_handshake_index_drop(struct noise_remote *);

static uint64_t	noise_counter_send(struct noise_counter *);
static bool	noise_counter_recv(struct noise_counter *, uint64_t);

static void	noise_kdf(uint8_t *, uint8_t *, uint8_t *, const uint8_t *,
            size_t, size_t, size_t, size_t,
            const uint8_t [NOISE_HASH_LEN]);
static bool	noise_mix_dh(
            uint8_t [NOISE_HASH_LEN],
            uint8_t [NOISE_SYMMETRIC_KEY_LEN],
            const uint8_t [NOISE_PUBLIC_KEY_LEN],
            const uint8_t [NOISE_PUBLIC_KEY_LEN]);
static bool	noise_mix_ss(
            uint8_t ck[NOISE_HASH_LEN],
            uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
            const uint8_t ss[NOISE_PUBLIC_KEY_LEN]);
static void	noise_mix_hash(
            uint8_t [NOISE_HASH_LEN],
            const uint8_t *,
            size_t);
static void	noise_mix_psk(
            uint8_t [NOISE_HASH_LEN],
            uint8_t [NOISE_HASH_LEN],
            uint8_t [NOISE_SYMMETRIC_KEY_LEN],
            const uint8_t [NOISE_SYMMETRIC_KEY_LEN]);
static void	noise_param_init(
            uint8_t [NOISE_HASH_LEN],
            uint8_t [NOISE_HASH_LEN],
            const uint8_t [NOISE_PUBLIC_KEY_LEN]);

static void	noise_msg_encrypt(uint8_t *, const uint8_t *, size_t,
            uint8_t [NOISE_SYMMETRIC_KEY_LEN],
            uint8_t [NOISE_HASH_LEN]);
static bool	noise_msg_decrypt(uint8_t *, const uint8_t *, size_t,
            uint8_t [NOISE_SYMMETRIC_KEY_LEN],
            uint8_t [NOISE_HASH_LEN]);
static void	noise_msg_ephemeral(
            uint8_t [NOISE_HASH_LEN],
            uint8_t [NOISE_HASH_LEN],
            const uint8_t src[NOISE_PUBLIC_KEY_LEN]);

static void	noise_tai64n_now(uint8_t [NOISE_TIMESTAMP_LEN]);

/* Set/Get noise parameters */
void
noise_local_init(struct noise_local *l, struct noise_upcall *upcall)
{
    clib_memset(l, 0, sizeof(*l));
    l->l_upcall = *upcall;
}

bool
noise_local_set_private(struct noise_local *l,
            uint8_t private[NOISE_PUBLIC_KEY_LEN])
{
    clib_memcpy(l->l_private, private, NOISE_PUBLIC_KEY_LEN);
    curve25519_clamp_secret(l->l_private);
    l->l_has_identity = curve25519_gen_public(l->l_public, private);

    return l->l_has_identity;
}

bool
noise_local_keys(struct noise_local *l, uint8_t public[NOISE_PUBLIC_KEY_LEN],
    uint8_t private[NOISE_PUBLIC_KEY_LEN])
{
    if (l->l_has_identity) {
        if (public != NULL)
            clib_memcpy(public, l->l_public, NOISE_PUBLIC_KEY_LEN);
        if (private != NULL)
            clib_memcpy(private, l->l_private, NOISE_PUBLIC_KEY_LEN);
    } else {
        return false;
    }
    return true;
}

void
noise_remote_init(struct noise_remote *r, uint32_t peer_pool_idx, uint8_t public[NOISE_PUBLIC_KEY_LEN],
    struct noise_local *l)
{
    clib_memset(r, 0, sizeof(*r));
    clib_memcpy(r->r_public, public, NOISE_PUBLIC_KEY_LEN);
    r->r_peer_idx = peer_pool_idx;

    ASSERT(l != NULL);
    r->r_local = l;
    r->r_handshake.hs_state = HS_ZEROED;
    noise_remote_precompute(r);
}

bool
noise_remote_set_psk(struct noise_remote *r,
    uint8_t psk[NOISE_SYMMETRIC_KEY_LEN])
{
    int same;
    same = !clib_memcmp(r->r_psk, psk, NOISE_SYMMETRIC_KEY_LEN);
    if (!same) {
        clib_memcpy(r->r_psk, psk, NOISE_SYMMETRIC_KEY_LEN);
    }
    return same == 0;
}

bool
noise_remote_keys(struct noise_remote *r, uint8_t public[NOISE_PUBLIC_KEY_LEN],
    uint8_t psk[NOISE_SYMMETRIC_KEY_LEN])
{
    static uint8_t null_psk[NOISE_SYMMETRIC_KEY_LEN];
    int ret;

    if (public != NULL)
        clib_memcpy(public, r->r_public, NOISE_PUBLIC_KEY_LEN);

    if (psk != NULL)
        clib_memcpy(psk, r->r_psk, NOISE_SYMMETRIC_KEY_LEN);
    ret = clib_memcmp(r->r_psk, null_psk, NOISE_SYMMETRIC_KEY_LEN);

    return ret;
}

void
noise_remote_precompute(struct noise_remote *r)
{
    struct noise_local *l = r->r_local;
    if (!l->l_has_identity)
        clib_memset(r->r_ss, 0, NOISE_PUBLIC_KEY_LEN);
    else if (!curve25519_gen_shared(r->r_ss, l->l_private, r->r_public))
        clib_memset(r->r_ss, 0, NOISE_PUBLIC_KEY_LEN);

    noise_remote_handshake_index_drop(r);
    secure_zero_memory(&r->r_handshake, sizeof(r->r_handshake));
}

/* Handshake functions */
bool
noise_create_initiation(struct noise_remote *r, uint32_t *s_idx,
    uint8_t ue[NOISE_PUBLIC_KEY_LEN],
    uint8_t es[NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN],
    uint8_t ets[NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN])
{
    struct noise_handshake *hs = &r->r_handshake;
    struct noise_local *l = r->r_local;
    uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
    int ret = false;

    if (!l->l_has_identity)
        goto error;
    noise_param_init(hs->hs_ck, hs->hs_hash, r->r_public);

    /* e */
    curve25519_gen_secret(hs->hs_e);
    if (!curve25519_gen_public(ue, hs->hs_e))
        goto error;
    noise_msg_ephemeral(hs->hs_ck, hs->hs_hash, ue);

    /* es */
    if (!noise_mix_dh(hs->hs_ck, key, hs->hs_e, r->r_public))
        goto error;

    /* s */
    noise_msg_encrypt(es, l->l_public,
        NOISE_PUBLIC_KEY_LEN, key, hs->hs_hash);

    /* ss */
    if (!noise_mix_ss(hs->hs_ck, key, r->r_ss))
        goto error;

    /* {t} */
    noise_tai64n_now(ets);
    noise_msg_encrypt(ets, ets,
        NOISE_TIMESTAMP_LEN, key, hs->hs_hash);
    noise_remote_handshake_index_drop(r);
    hs->hs_state = CREATED_INITIATION;
    hs->hs_local_index = noise_remote_handshake_index_get(r);
    *s_idx = hs->hs_local_index;
    ret = true;
error:
    secure_zero_memory(key, NOISE_SYMMETRIC_KEY_LEN);
    return ret;
}

bool
noise_consume_initiation(struct noise_local *l, struct noise_remote **rp,
    uint32_t s_idx, uint8_t ue[NOISE_PUBLIC_KEY_LEN],
    uint8_t es[NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN],
    uint8_t ets[NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN])
{
    struct noise_remote *r;
    struct noise_handshake hs;
    uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
    uint8_t r_public[NOISE_PUBLIC_KEY_LEN];
    uint8_t	timestamp[NOISE_TIMESTAMP_LEN];
    int ret = false;

    if (!l->l_has_identity)
        goto error;
    noise_param_init(hs.hs_ck, hs.hs_hash, l->l_public);

    /* e */
    noise_msg_ephemeral(hs.hs_ck, hs.hs_hash, ue);

    /* es */
    if (!noise_mix_dh(hs.hs_ck, key, l->l_private, ue))
        goto error;

    /* s */
    if (!noise_msg_decrypt(r_public, es,
        NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN, key, hs.hs_hash))
        goto error;

    /* Lookup the remote we received from */
    if ((r = l->l_upcall.u_remote_get(r_public)) == NULL)
        goto error;

    /* ss */
    if (!noise_mix_ss(hs.hs_ck, key, r->r_ss))
        goto error;

    /* {t} */
    if (!noise_msg_decrypt(timestamp, ets,
        NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN, key, hs.hs_hash))
        goto error;

    hs.hs_state = CONSUMED_INITIATION;
    hs.hs_local_index = 0;
    hs.hs_remote_index = s_idx;
    clib_memcpy(hs.hs_e, ue, NOISE_PUBLIC_KEY_LEN);

    /* Replay */
    if (clib_memcmp(timestamp, r->r_timestamp, NOISE_TIMESTAMP_LEN) > 0)
        clib_memcpy(r->r_timestamp, timestamp, NOISE_TIMESTAMP_LEN);
    else
        goto error;

//    /* Flood attack */
//    if (wg_birthdate_has_expired(r->r_last_init, 0, REJECT_INTERVAL)) // ????
//        getnanouptime(&r->r_last_init);
//    else
//        goto error;

    /* Ok, we're happy to accept this initiation now */
    noise_remote_handshake_index_drop(r);
    r->r_handshake = hs;
    *rp = r;
    ret = true;
error:
    secure_zero_memory(key, NOISE_SYMMETRIC_KEY_LEN);
    secure_zero_memory(&hs, sizeof(hs));
    return ret;
}

bool
noise_create_response(struct noise_remote *r, uint32_t *s_idx, uint32_t *r_idx,
    uint8_t ue[NOISE_PUBLIC_KEY_LEN], uint8_t en[0 + NOISE_AUTHTAG_LEN])
{
    struct noise_handshake *hs = &r->r_handshake;
    uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
    uint8_t e[NOISE_PUBLIC_KEY_LEN];
    int ret = false;

    if (hs->hs_state != CONSUMED_INITIATION)
        goto error;

    /* e */
    curve25519_gen_secret(e);
    if (!curve25519_gen_public(ue, e))
        goto error;
    noise_msg_ephemeral(hs->hs_ck, hs->hs_hash, ue);

    /* ee */
    if (!noise_mix_dh(hs->hs_ck, NULL, e, hs->hs_e))
        goto error;

    /* se */
    if (!noise_mix_dh(hs->hs_ck, NULL, e, r->r_public))
        goto error;

    /* psk */
    noise_mix_psk(hs->hs_ck, hs->hs_hash, key, r->r_psk);

    /* {} */
    noise_msg_encrypt(en, NULL, 0, key, hs->hs_hash);

    hs->hs_state = CREATED_RESPONSE;
    hs->hs_local_index = noise_remote_handshake_index_get(r);
    *r_idx = hs->hs_remote_index;
    *s_idx = hs->hs_local_index;
    ret = true;
error:
    secure_zero_memory(key, NOISE_SYMMETRIC_KEY_LEN);
    secure_zero_memory(e, NOISE_PUBLIC_KEY_LEN);
    return ret;
}

bool
noise_consume_response(struct noise_remote *r, uint32_t s_idx, uint32_t r_idx,
    uint8_t ue[NOISE_PUBLIC_KEY_LEN], uint8_t en[0 + NOISE_AUTHTAG_LEN])
{
    struct noise_local *l = r->r_local;
    struct noise_handshake hs;
    uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
    uint8_t preshared_key[NOISE_PUBLIC_KEY_LEN];
    int ret = false;

    if (!l->l_has_identity)
        goto error;

    hs = r->r_handshake;
    clib_memcpy(preshared_key, r->r_psk, NOISE_SYMMETRIC_KEY_LEN);

    if (hs.hs_state != CREATED_INITIATION ||
        hs.hs_local_index != r_idx)
        goto error;

    /* e */
    noise_msg_ephemeral(hs.hs_ck, hs.hs_hash, ue);

    /* ee */
    if (!noise_mix_dh(hs.hs_ck, NULL, hs.hs_e, ue))
        goto error;

    /* se */
    if (!noise_mix_dh(hs.hs_ck, NULL, l->l_private, ue))
        goto error;

    /* psk */
    noise_mix_psk(hs.hs_ck, hs.hs_hash, key, preshared_key);

    /* {} */
    if (!noise_msg_decrypt(NULL, en,
        0 + NOISE_AUTHTAG_LEN, key, hs.hs_hash))
        goto error;

    hs.hs_remote_index = s_idx;

    if (r->r_handshake.hs_state == hs.hs_state &&
        r->r_handshake.hs_local_index == hs.hs_local_index) {
        r->r_handshake = hs;
        r->r_handshake.hs_state = CONSUMED_RESPONSE;
        ret = true;
    }
error:
    secure_zero_memory(&hs, sizeof(hs));
    secure_zero_memory(key, NOISE_SYMMETRIC_KEY_LEN);
    return ret;
}

bool
noise_remote_begin_session(struct noise_remote *r)
{
    struct noise_handshake *hs = &r->r_handshake;
    struct noise_keypair kp, *next, *current, *previous;

    /* We now derive the keypair from the handshake */
    if (hs->hs_state == CONSUMED_RESPONSE) {
        kp.kp_is_initiator = 1;
        noise_kdf(kp.kp_send, kp.kp_recv, NULL, NULL,
            NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, 0,
            hs->hs_ck);
    } else if (hs->hs_state == CREATED_RESPONSE) {
        kp.kp_is_initiator = 0;
        noise_kdf(kp.kp_recv, kp.kp_send, NULL, NULL,
            NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, 0,
            hs->hs_ck);
    } else {
        return false;
    }

    kp.kp_valid = 1;
    kp.kp_local_index = hs->hs_local_index;
    kp.kp_remote_index = hs->hs_remote_index;
    kp.kp_birthdate = vlib_time_now (vlib_get_main()); // ????
    clib_memset(&kp.kp_ctr, 0, sizeof(kp.kp_ctr));

    /* Now we need to add_new_keypair */
    next = r->r_next;
    current = r->r_current;
    previous = r->r_previous;

    if (kp.kp_is_initiator) {
        if (next != NULL) {
            r->r_next = NULL;
            r->r_previous = next;
            noise_remote_keypair_free(r, &current);
        } else {
            r->r_previous = current;
        }

        noise_remote_keypair_free(r, &previous);

        r->r_current = noise_remote_keypair_allocate(r);
        *r->r_current = kp;
    } else {
        noise_remote_keypair_free(r, &next);
        r->r_previous = NULL;
        noise_remote_keypair_free(r, &previous);

        r->r_next = noise_remote_keypair_allocate(r);
        *r->r_next = kp;
    }
    secure_zero_memory(&r->r_handshake, sizeof(r->r_handshake));
    secure_zero_memory(&kp, sizeof(kp));
    return true;
}

void
noise_remote_clear(struct noise_remote *r)
{
    noise_remote_handshake_index_drop(r);
    secure_zero_memory(&r->r_handshake, sizeof(r->r_handshake));

    noise_remote_keypair_free(r, &r->r_next);
    noise_remote_keypair_free(r, &r->r_current);
    noise_remote_keypair_free(r, &r->r_previous);
    r->r_next = NULL;
    r->r_current = NULL;
    r->r_previous = NULL;
}

void
noise_remote_expire_current(struct noise_remote *r)
{
    if (r->r_next != NULL)
        r->r_next->kp_valid = 0;
    if (r->r_current != NULL)
        r->r_current->kp_valid = 0;
}

bool
noise_remote_ready(struct noise_remote *r)
{
    struct noise_keypair *kp;
    int ret;

    if ((kp = r->r_current) == NULL ||
        !kp->kp_valid ||
        wg_birthdate_has_expired (kp->kp_birthdate, REJECT_AFTER_TIME) ||
        kp->kp_ctr.c_recv >= REJECT_AFTER_MESSAGES ||
        kp->kp_ctr.c_send >= REJECT_AFTER_MESSAGES)
        ret = false;
    else
        ret = true;
    return ret;
}

enum noise_state_crypt
noise_remote_encrypt(struct noise_remote *r, uint32_t *r_idx, uint64_t *nonce,
    uint8_t *src, size_t srclen, uint8_t *dst)
{
    struct noise_keypair *kp;
    enum noise_state_crypt ret = SC_FAILED;

    if ((kp = r->r_current) == NULL)
        goto error;

    /* We confirm that our values are within our tolerances. We want:
     *  - a valid keypair
     *  - our keypair to be less than REJECT_AFTER_TIME seconds old
     *  - our receive counter to be less than REJECT_AFTER_MESSAGES
     *  - our send counter to be less than REJECT_AFTER_MESSAGES
     *
     * kp_ctr isn't locked here, we're happy to accept a racy read. */
    if (!kp->kp_valid ||
        wg_birthdate_has_expired(kp->kp_birthdate, REJECT_AFTER_TIME) ||
        kp->kp_ctr.c_recv >= REJECT_AFTER_MESSAGES ||
        ((*nonce = noise_counter_send(&kp->kp_ctr)) > REJECT_AFTER_MESSAGES))
        goto error;

    /* We encrypt into the same buffer, so the caller must ensure that buf
     * has NOISE_AUTHTAG_LEN bytes to store the MAC. The nonce and index
     * are passed back out to the caller through the provided data pointer. */
    *r_idx = kp->kp_remote_index;
    chacha20poly1305_encrypt(dst, src, srclen,
        NULL, 0, *nonce, kp->kp_send);

    /* If our values are still within tolerances, but we are approaching
     * the tolerances, we notify the caller with ESTALE that they should
     * establish a new keypair. The current keypair can continue to be used
     * until the tolerances are hit. We notify if:
     *  - our send counter is valid and not less than REKEY_AFTER_MESSAGES
     *  - we're the initiator and our keypair is older than
     *    REKEY_AFTER_TIME seconds */
    ret = SC_KEEP_KEY_FRESH;
    if ((kp->kp_valid && *nonce >= REKEY_AFTER_MESSAGES) ||
        (kp->kp_is_initiator &&
        wg_birthdate_has_expired(kp->kp_birthdate, REKEY_AFTER_TIME)))
        goto error;

    ret = SC_OK;
error:
    return ret;
}

enum noise_state_crypt
noise_remote_decrypt(struct noise_remote *r, uint32_t r_idx, uint64_t nonce,
    uint8_t *src, size_t srclen, uint8_t *dst)
{
    struct noise_keypair *kp;
    enum noise_state_crypt ret = SC_FAILED;

    if (r->r_current != NULL && r->r_current->kp_local_index == r_idx) {
        kp = r->r_current;
    } else if (r->r_previous != NULL && r->r_previous->kp_local_index == r_idx) {
        kp = r->r_previous;
    } else if (r->r_next != NULL && r->r_next->kp_local_index == r_idx) {
        kp = r->r_next;
    } else {
        goto error;
    }

    /* We confirm that our values are within our tolerances. These values
     * are the same as the encrypt routine.
     *
     * kp_ctr isn't locked here, we're happy to accept a racy read. */
    if (wg_birthdate_has_expired(kp->kp_birthdate, REJECT_AFTER_TIME) ||
        kp->kp_ctr.c_recv >= REJECT_AFTER_MESSAGES)
        goto error;

    /* Decrypt, then validate the counter. We don't want to validate the
     * counter before decrypting as we do not know the message is authentic
     * prior to decryption. */
    if (chacha20poly1305_decrypt(dst, src, srclen,
        NULL, 0, nonce, kp->kp_recv) == 0)
        goto error;

    if (!noise_counter_recv(&kp->kp_ctr, nonce))
        goto error;

    /* If we've received the handshake confirming data packet then move the
     * next keypair into current. If we do slide the next keypair in, then
     * we skip the REKEY_AFTER_TIME_RECV check. This is safe to do as a
     * data packet can't confirm a session that we are an INITIATOR of. */
    if (kp == r->r_next) {
        if (kp == r->r_next && kp->kp_local_index == r_idx) {
            noise_remote_keypair_free(r, &r->r_previous);
            r->r_previous = r->r_current;
            r->r_current = r->r_next;
            r->r_next = NULL;

            ret = SC_CONN_RESET;
            goto error;
        }
    }

    /* Similar to when we encrypt, we want to notify the caller when we
     * are approaching our tolerances. We notify if:
     *  - we're the initiator and the current keypair is older than
     *    REKEY_AFTER_TIME_RECV seconds. */
    ret = SC_KEEP_KEY_FRESH;
    kp = r->r_current;
    if (kp != NULL &&
        kp->kp_valid &&
        kp->kp_is_initiator &&
        wg_birthdate_has_expired(kp->kp_birthdate, REKEY_AFTER_TIME_RECV)) // TODO Check this
        goto error;

    ret = SC_OK;
error:
    return ret;
}

/* Private functions - these should not be called outside this file under any
 * circumstances. */
static struct noise_keypair *
noise_remote_keypair_allocate(struct noise_remote *r)
{
    struct noise_keypair *kp;
    kp = clib_mem_alloc (sizeof (*kp));
    return kp;
}

static void
noise_remote_keypair_free(struct noise_remote *r, struct noise_keypair **kp) // TODO Check this
{
    struct noise_upcall *u = &r->r_local->l_upcall;
    if (*kp) {
        u->u_index_drop((*kp)->kp_local_index);

        clib_memset((*kp)->kp_send, 0, sizeof((*kp)->kp_send));
        clib_memset((*kp)->kp_recv, 0, sizeof((*kp)->kp_recv));
        clib_mem_free (*kp);
    }
}

static uint32_t
noise_remote_handshake_index_get(struct noise_remote *r)
{
    struct noise_upcall *u = &r->r_local->l_upcall;
    return u->u_index_set(r);
}

static void
noise_remote_handshake_index_drop(struct noise_remote *r)
{
    struct noise_handshake *hs = &r->r_handshake;
    struct noise_upcall *u = &r->r_local->l_upcall;
    if (hs->hs_state != HS_ZEROED)
        u->u_index_drop(hs->hs_local_index);
}

static uint64_t
noise_counter_send(struct noise_counter *ctr)
{
    uint64_t ret = ctr->c_send++;
    return ret;
}

static bool
noise_counter_recv(struct noise_counter *ctr, uint64_t recv)
{
    uint64_t i, top, index_recv, index_ctr;
    unsigned long bit;
    bool ret = false;


    /* Check that the recv counter is valid */
    if (ctr->c_recv >= REJECT_AFTER_MESSAGES ||
        recv >= REJECT_AFTER_MESSAGES)
        goto error;

    /* If the packet is out of the window, invalid */
    if (recv + COUNTER_WINDOW_SIZE < ctr->c_recv)
        goto error;

    /* If the new counter is ahead of the current counter, we'll need to
     * zero out the bitmap that has previously been used */
    index_recv = recv / COUNTER_BITS;
    index_ctr = ctr->c_recv / COUNTER_BITS;

    if (recv > ctr->c_recv) {
        top = clib_min(index_recv - index_ctr, COUNTER_NUM);
        for (i = 1; i <= top; i++)
            ctr->c_backtrack[
                (i + index_ctr) & (COUNTER_NUM - 1)] = 0;
        ctr->c_recv = recv;
    }

    index_recv %= COUNTER_NUM;
    bit = 1ul << (recv % COUNTER_BITS);

    if (ctr->c_backtrack[index_recv] & bit)
        goto error;

    ctr->c_backtrack[index_recv] |= bit;

    ret = true;
error:
    return ret;
}

static void
noise_kdf(uint8_t *a, uint8_t *b, uint8_t *c, const uint8_t *x,
    size_t a_len, size_t b_len, size_t c_len, size_t x_len,
    const uint8_t ck[NOISE_HASH_LEN])
{
    uint8_t out[BLAKE2S_HASHSIZE + 1];
    uint8_t sec[BLAKE2S_HASHSIZE];

    /* Extract entropy from "x" into sec */
    u32 l = 0;
    HMAC (EVP_blake2s256 (), ck, NOISE_HASH_LEN, x, x_len,
      sec, &l);
    ASSERT (l == BLAKE2S_HASHSIZE);

    if (a == NULL || a_len == 0)
        goto out;

    /* Expand first key: key = sec, data = 0x1 */
    out[0] = 1;
    HMAC (EVP_blake2s256 (), sec, BLAKE2S_HASHSIZE, out, 1, out, &l);
    ASSERT (l == BLAKE2S_HASHSIZE);
    clib_memcpy(a, out, a_len);

    if (b == NULL || b_len == 0)
        goto out;

    /* Expand second key: key = sec, data = "a" || 0x2 */
    out[BLAKE2S_HASHSIZE] = 2;
    HMAC (EVP_blake2s256 (), sec, BLAKE2S_HASHSIZE, out,
      BLAKE2S_HASHSIZE + 1, out, &l);
    ASSERT (l == BLAKE2S_HASHSIZE);
    clib_memcpy(b, out, b_len);

    if (c == NULL || c_len == 0)
        goto out;

    /* Expand third key: key = sec, data = "b" || 0x3 */
    out[BLAKE2S_HASHSIZE] = 3;
    HMAC (EVP_blake2s256 (), sec, BLAKE2S_HASHSIZE, out,
      BLAKE2S_HASHSIZE + 1, out, &l);
    ASSERT (l == BLAKE2S_HASHSIZE);

    clib_memcpy (c, out, c_len);

out:
    /* Clear sensitive data from stack */
    secure_zero_memory (sec, BLAKE2S_HASHSIZE);
    secure_zero_memory (out, BLAKE2S_HASHSIZE + 1);
}

static bool
noise_mix_dh(uint8_t ck[NOISE_HASH_LEN], uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
    const uint8_t private[NOISE_PUBLIC_KEY_LEN],
    const uint8_t public[NOISE_PUBLIC_KEY_LEN])
{
    uint8_t dh[NOISE_PUBLIC_KEY_LEN];
    if (!curve25519_gen_shared(dh, private, public))
        return false;
    noise_kdf(ck, key, NULL, dh,
        NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN, ck);
    secure_zero_memory(dh, NOISE_PUBLIC_KEY_LEN);
    return true;
}

static bool
noise_mix_ss(uint8_t ck[NOISE_HASH_LEN], uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
    const uint8_t ss[NOISE_PUBLIC_KEY_LEN])
{
    static uint8_t null_point[NOISE_PUBLIC_KEY_LEN];
    if (clib_memcmp(ss, null_point, NOISE_PUBLIC_KEY_LEN) == 0)
        return false;
    noise_kdf(ck, key, NULL, ss,
        NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN, ck);
    return true;
}

static void
noise_mix_hash(uint8_t hash[NOISE_HASH_LEN], const uint8_t *src,
    size_t src_len)
{
    struct blake2s_state blake;

    blake2s_init(&blake, NOISE_HASH_LEN);
    blake2s_update(&blake, hash, NOISE_HASH_LEN);
    blake2s_update(&blake, src, src_len);
    blake2s_final(&blake, hash, NOISE_HASH_LEN);
}

static void
noise_mix_psk(uint8_t ck[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN],
    uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
    const uint8_t psk[NOISE_SYMMETRIC_KEY_LEN])
{
    uint8_t tmp[NOISE_HASH_LEN];

    noise_kdf(ck, tmp, key, psk,
        NOISE_HASH_LEN, NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN,
        NOISE_SYMMETRIC_KEY_LEN, ck);
    noise_mix_hash(hash, tmp, NOISE_HASH_LEN);
    secure_zero_memory(tmp, NOISE_HASH_LEN);
}

static void
noise_param_init(uint8_t ck[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN],
    const uint8_t s[NOISE_PUBLIC_KEY_LEN])
{
    struct blake2s_state blake;

    blake2s (ck, NOISE_HASH_LEN, (uint8_t *)NOISE_HANDSHAKE_NAME,
         strlen(NOISE_HANDSHAKE_NAME), NULL, 0);
    blake2s_init(&blake, NOISE_HASH_LEN);
    blake2s_update(&blake, ck, NOISE_HASH_LEN);
    blake2s_update(&blake, (uint8_t *)NOISE_IDENTIFIER_NAME,
        strlen(NOISE_IDENTIFIER_NAME));
    blake2s_final(&blake, hash, NOISE_HASH_LEN);

    noise_mix_hash(hash, s, NOISE_PUBLIC_KEY_LEN);
}

static void
noise_msg_encrypt(uint8_t *dst, const uint8_t *src, size_t src_len,
    uint8_t key[NOISE_SYMMETRIC_KEY_LEN], uint8_t hash[NOISE_HASH_LEN])
{
    /* Nonce always zero for Noise_IK */
    chacha20poly1305_encrypt(dst, src, src_len,
        hash, NOISE_HASH_LEN, 0, key);
    noise_mix_hash(hash, dst, src_len + NOISE_AUTHTAG_LEN);
}

static bool
noise_msg_decrypt(uint8_t *dst, const uint8_t *src, size_t src_len,
    uint8_t key[NOISE_SYMMETRIC_KEY_LEN], uint8_t hash[NOISE_HASH_LEN])
{
    /* Nonce always zero for Noise_IK */
    if (!chacha20poly1305_decrypt(dst, src, src_len,
        hash, NOISE_HASH_LEN, 0, key))
        return false;
    noise_mix_hash(hash, src, src_len);
    return true;
}

static void
noise_msg_ephemeral(uint8_t ck[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN],
    const uint8_t src[NOISE_PUBLIC_KEY_LEN])
{
    noise_mix_hash(hash, src, NOISE_PUBLIC_KEY_LEN);
    noise_kdf(ck, NULL, NULL, src, NOISE_HASH_LEN, 0, 0,
          NOISE_PUBLIC_KEY_LEN, ck);
}

static void
noise_tai64n_now(uint8_t output[NOISE_TIMESTAMP_LEN])
{
    uint32_t unix_sec;
    uint32_t unix_nanosec;

    uint64_t sec;
    uint32_t nsec;

    unix_time_now_nsec_fraction(&unix_sec, &unix_nanosec);

    /* Round down the nsec counter to limit precise timing leak. */
    unix_nanosec &= REJECT_INTERVAL_MASK;

    /* https://cr.yp.to/libtai/tai64.html */
    sec = htobe64(0x400000000000000aULL + unix_sec);
    nsec = htobe32(unix_nanosec);

    /* memcpy to output buffer, assuming output could be unaligned. */
    clib_memcpy(output, &sec, sizeof(sec));
    clib_memcpy(output + sizeof(sec), &nsec, sizeof(nsec));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
