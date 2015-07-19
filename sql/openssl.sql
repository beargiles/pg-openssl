/*
 * Author: Bear Giles <bgiles@coyotesong.com>
 * Created at: 2015-07-17 18:58:48 -0600
 *
 */
SET client_min_messages = warning;

DROP TYPE IF EXISTS x CASCADE;

CREATE TYPE cipher_info AS (
    name           text,
    block_size     int,
    key_length     int,
    iv_length      int,
    mode           text,
    var_length     bool,
    custom_iv      bool,
    custom_keylen  bool,
    uses_rand_key  bool,
    fips_safe      bool,
    nid            int
);

CREATE TYPE digest_info AS (
    name           text,
    block_size     int,
    digest_length  int,
    pkey_type      int,
    fips_safe      bool,
    nid            int
);

CREATE OR REPLACE FUNCTION list_ciphers()
RETURNS SETOF cipher_info
AS 'pg_openssl', 'pgx_openssl_list_ciphers'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION list_digests()
RETURNS SETOF digest_info
AS 'pg_openssl', 'pgx_openssl_list_digests'
LANGUAGE C STRICT;
