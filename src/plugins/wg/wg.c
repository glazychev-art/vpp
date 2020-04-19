/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ipip/ipip.h>
#include <vpp/app/version.h>
#include <vnet/udp/udp.h>

#include <wg/wg_send.h>
#include <wg/wg_convert.h>
#include <wg/wg.h>

wg_main_t wg_main;

static vnet_api_error_t
wg_register_udp_port (vlib_main_t * vm, u16 port)
{
  udp_dst_port_info_t *pi = udp_get_dst_port_info (&udp_main, port, UDP_IP4);
  if (pi)
    return VNET_API_ERROR_VALUE_EXIST;

  udp_register_dst_port (vm, port, wg_input_node.index, 1);
  return 0;
}

static vnet_api_error_t
wg_unregister_udp_port (vlib_main_t * vm, u16 port)
{
  if (port)
    {
      udp_unregister_dst_port (vm, port, 1);
    }
  return 0;
}

clib_error_t *
wg_device_set (wg_main_t * wmp, char private_key_64[NOISE_KEY_LEN_BASE64],
	       u16 port)
{
  clib_error_t *error = NULL;

  if (!wmp->is_inited)
    {
      u8 private_key[NOISE_PUBLIC_KEY_LEN];

      if (!key_from_base64 (private_key, private_key_64))
	{
	  error = clib_error_return (0, "Error parce private key");
	  return error;
	}

      f64 now = vlib_time_now (wmp->vlib_main);
      vnet_api_error_t ret = wg_register_udp_port (wmp->vlib_main, port);
      if (ret == VNET_API_ERROR_VALUE_EXIST)
	{
	  error =
	    clib_error_return (0, "UDP port %d is already taken", (u16) port);
	  return error;
	}

      wmp->port_src = port;

      wg_noise_init ();
      wg_cookie_checker_init (&wmp->cookie_checker, now);
      wg_noise_set_static_identity_private_key (&wmp->static_identity,
						private_key);
      wg_cookie_checker_precompute_keys (&wmp->cookie_checker,
					 &wmp->static_identity);
      wmp->is_inited = true;
    }
  else
    {
      error = clib_error_return (0, "Remove existing device before");
      return error;
    }

  return error;
}

clib_error_t *
wg_device_clear (wg_main_t * wmp)
{
  clib_error_t *error = NULL;

  u32 *remove_idxs = 0;
  wg_peer_t *peer;
  wg_unregister_udp_port (wmp->vlib_main, wmp->port_src);

  pool_foreach (peer, wmp->peers, (
				    {
				    vnet_feature_enable_disable ("ip4-output",
								 "wg-output-tun",
								 peer->tun_sw_if_index,
								 0, 0, 0);
				    ipip_del_tunnel (peer->tun_sw_if_index);
				    wg_peer_clear (peer,
						   vlib_time_now
						   (wmp->vlib_main));
				    vec_add1 (remove_idxs, peer - wmp->peers);
				    }
		));

  u32 *idx;
  vec_foreach (idx, remove_idxs)
  {
    pool_put_index (wmp->peers, *idx);
  }
  clib_memset (&wmp->cookie_checker, 0, sizeof (wmp->cookie_checker));
  clib_memset (&wmp->static_identity, 0, sizeof (wmp->static_identity));
  wmp->is_inited = false;

  return error;
}

clib_error_t *
wg_peer_set (wg_main_t * wmp, char public_key_64[NOISE_KEY_LEN_BASE64],
	     ip4_address_t endpoint, ip4_address_t allowed_ip,
         u16 port, u32 tun_sw_if_index, u16 persistent_keepalive)
{
  clib_error_t *error = NULL;

  u8 public_key[NOISE_PUBLIC_KEY_LEN];
  if (!key_from_base64 (public_key, public_key_64))
    {
      error = clib_error_return (0, "Error parce public key");
      return error;
    }

  if (tun_sw_if_index == ~0)
    {
      error = clib_error_return (0, "Tunnel is not specified");
      return error;
    }

  if (pool_elts (wmp->peers) > MAX_PEERS)
    {
      error = clib_error_return (0, "Max peers limit");
      return error;
    }

  if (!wmp->is_inited)
    {
      error = clib_error_return (0, "wg device parameters is not set");
      return error;
    }

  f64 now = vlib_time_now (wmp->vlib_main);
  wg_peer_t *peer;
  pool_get (wmp->peers, peer);

  wg_peer_init (peer, now);
  wg_peer_fill (peer, endpoint, (u16) port, persistent_keepalive, allowed_ip,
		tun_sw_if_index, now);
  wg_noise_handshake_init (peer, &wmp->static_identity, public_key, NULL);
  wg_cookie_checker_precompute_peer_keys (peer);

  vnet_feature_enable_disable ("ip4-output", "wg-output-tun",
			       tun_sw_if_index, 1, 0, 0);

  if (peer->persistent_keepalive_interval != 0)
    {
      wg_send_keepalive (wmp->vlib_main, peer);
    }

  return error;
}

clib_error_t *
wg_peer_remove (wg_main_t * wmp, char public_key_64[NOISE_KEY_LEN_BASE64])
{
  clib_error_t *error = NULL;

  wg_peer_t *peer_pool = wmp->peers;
  wg_peer_t *peer = NULL;
  u32 peerIdx = ~0;
  u8 public_key[NOISE_PUBLIC_KEY_LEN];

  if (!key_from_base64 (public_key, public_key_64))
    {
      error = clib_error_return (0, "Error parce public key");
      return error;
    }

  pool_foreach (peer, peer_pool, (
				   {
				   if (!memcmp
				       (peer->handshake.remote_static,
					public_key, NOISE_PUBLIC_KEY_LEN))
				   {
				   vnet_feature_enable_disable ("ip4-output",
								"wg-output-tun",
								peer->tun_sw_if_index,
								0, 0, 0);
				   ipip_del_tunnel (peer->tun_sw_if_index);
				   wg_peer_clear (peer,
						  vlib_time_now
						  (wmp->vlib_main));
				   peerIdx = peer - peer_pool; break;}
				   }
		));
  pool_put_index (peer_pool, peerIdx);
  return error;
}

static clib_error_t *
wg_init (vlib_main_t * vm)
{
  wg_main_t *wmp = &wg_main;
  clib_error_t *error = 0;

  wmp->vlib_main = vm;
  wmp->is_inited = false;
  wmp->peers = 0;

  return error;
}

VLIB_INIT_FUNCTION (wg_init);

/* *INDENT-OFF* */

VNET_FEATURE_INIT (wg_output_tun, static) =
{
  .arc_name = "ip4-output",
  .node_name = "wg-output-tun",
};


VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */