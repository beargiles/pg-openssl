\set ECHO none
BEGIN;
\i sql/openssl.sql
\set ECHO all

--
-- list ciphers.
--
-- Note: this test may fail in future when openssl library is updated.
--
select * from pgx_openssl_list_ciphers();

--
-- list digests.
--
-- Note: this test may fail in future when openssl library is updated.
--
select * from pgx_openssl_list_digests() limit 20;

ROLLBACK;
