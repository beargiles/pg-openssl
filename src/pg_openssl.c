#include "postgres.h"
#include "fmgr.h"
#include "executor/executor.h"
#include "funcapi.h"
#include "access/htup_details.h"
#include <openssl/err.h>
#include <openssl/ssl.h>

PG_MODULE_MAGIC;

/**
 * List of object names. Limit of 100 entries is a guess.
 */
typedef struct {
    int cnt;
    const OBJ_NAME *names[100];
} ListOfObjNames;

/**
 * Callback when obtaining list of object names.
 */
static void capture_obj_names(const OBJ_NAME *name, void *data) {
    ListOfObjNames *x = (ListOfObjNames *) data;

    if (!islower((unsigned char) *name->name))
        return;

    if (x->cnt < sizeof(x->names) / sizeof(x->names[0])) {
        x->names[x->cnt++] = name;
    }
}

/**
 * Return list of ciphers
 */
PG_FUNCTION_INFO_V1(pgx_openssl_list_ciphers);

Datum
pgx_openssl_list_ciphers(PG_FUNCTION_ARGS) {
    FuncCallContext *funcctx;
    TupleDesc tupdesc;
    AttInMetadata *attinmeta = NULL;
    ListOfObjNames *x = NULL;

    if (SRF_IS_FIRSTCALL()) {
    	MemoryContext oldContext;

        funcctx = SRF_FIRSTCALL_INIT();
        oldContext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

        // Build a tuple descriptor for our result type
        if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
             ereport(ERROR,
                 (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                  errmsg("function returning record called in context that cannot accept type record")));

        // generate attribute metadata needed later to produce tuples 
        // from raw C strings
        attinmeta = TupleDescGetAttInMetadata(tupdesc);
        funcctx->attinmeta = attinmeta;

        // get list of ciphers
        x = (ListOfObjNames *) palloc(sizeof(ListOfObjNames));
        OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH, capture_obj_names, x);

		// set up function context for future calls.
        funcctx->user_fctx = x;
        funcctx->max_calls = x->cnt;

        MemoryContextSwitchTo(oldContext);
    }

    funcctx = SRF_PERCALL_SETUP();
    attinmeta = funcctx->attinmeta;
    x = (ListOfObjNames *) funcctx->user_fctx;

    if (funcctx->call_cntr < funcctx->max_calls) {
        HeapTuple tuple;
        Datum result;
        char **values, *data, *mode;
        int i;

        int idx = funcctx->call_cntr;
		const EVP_CIPHER *cipher = EVP_get_cipherbyname(x->names[idx]->name);
        long flags = EVP_CIPHER_flags(cipher);

        values = (char **) palloc(11 * sizeof(char *));
        data = (char *) palloc(11 * 16);
        memset(data, 0, 11 * 16);
        for (i = 1; i < 11; i++) {
            values[i] = data + 16 * i;
        }
        values[0] = pstrdup(x->names[idx]->name);
        
        snprintf(values[1], 16, "%d", EVP_CIPHER_block_size(cipher));
        snprintf(values[2], 16, "%d", EVP_CIPHER_key_length(cipher));
        snprintf(values[3], 16, "%d", EVP_CIPHER_iv_length(cipher));

		switch(flags & EVP_CIPH_MODE) {
    		case EVP_CIPH_STREAM_CIPHER: mode = "STREAM"; break;
	   	    case EVP_CIPH_ECB_MODE: mode = "ECB"; break;
            case EVP_CIPH_CBC_MODE: mode = "CBC"; break;
            case EVP_CIPH_CFB_MODE: mode = "CFB"; break;
            case EVP_CIPH_OFB_MODE: mode = "OFB"; break;
            case EVP_CIPH_CTR_MODE: mode = "CTR"; break;
            case EVP_CIPH_GCM_MODE: mode = "GCM"; break;
            case EVP_CIPH_CCM_MODE: mode = "CCM"; break;
            case EVP_CIPH_XTS_MODE: mode = "XTS"; break;
            default: mode = NULL;
        }
        if (mode != NULL) {
            values[4] = pstrdup(mode);
        }

        snprintf(values[5], 16, "%c", flags & EVP_CIPH_VARIABLE_LENGTH ? 't' : 'f');
        snprintf(values[6], 16, "%c", flags & EVP_CIPH_CUSTOM_IV ? 't' : 'f');
        snprintf(values[7], 16, "%c", flags & EVP_CIPH_CUSTOM_KEY_LENGTH ? 't' : 'f');
        snprintf(values[8], 16, "%c", flags & EVP_CIPH_RAND_KEY ? 't' : 'f');
        snprintf(values[9], 16, "%c", flags & EVP_CIPH_FLAG_FIPS ? 't' : 'f');
        snprintf(values[10], 16, "%d", EVP_CIPHER_nid(cipher));

        // snprintf(values[11], 16, "%c", flags & EVP_CIPH_NO_PADDING ? 't' : 'f');
        // snprintf(values[12], 16, "%c", flags & EVP_CIPH_FLAG_LENGTH_BITS ? 't' : 'f');
        // snprintf(values[13], 16, "%c", flags & EVP_CIPH_FLAG_NON_FIPS_ALLOW ? 't' : 'f');

        tuple = BuildTupleFromCStrings(attinmeta, values);
        result = HeapTupleGetDatum(tuple);

        SRF_RETURN_NEXT(funcctx, result);
    } else {
        SRF_RETURN_DONE(funcctx);
    }
}

/**
 * Return list of digests
 */
PG_FUNCTION_INFO_V1(pgx_openssl_list_digests);

Datum
pgx_openssl_list_digests(PG_FUNCTION_ARGS) {
    FuncCallContext *funcctx;
    TupleDesc tupdesc;
    AttInMetadata *attinmeta = NULL;
    ListOfObjNames *x = NULL;

    if (SRF_IS_FIRSTCALL()) {
    	MemoryContext oldContext;

        funcctx = SRF_FIRSTCALL_INIT();
        oldContext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

        // Build a tuple descriptor for our result type
        if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
             ereport(ERROR,
                 (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                  errmsg("function returning record called in context that cannot accept type record")));

        // generate attribute metadata needed later to produce tuples 
        // from raw C strings
        attinmeta = TupleDescGetAttInMetadata(tupdesc);
        funcctx->attinmeta = attinmeta;

        // get list of ciphers
        x = (ListOfObjNames *) palloc(sizeof(ListOfObjNames));
        OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_MD_METH, capture_obj_names, x);

		// set up function context for future calls.
        funcctx->user_fctx = x;
        funcctx->max_calls = x->cnt;
        funcctx->max_calls = 1;

        MemoryContextSwitchTo(oldContext);
    }

    funcctx = SRF_PERCALL_SETUP();
    attinmeta = funcctx->attinmeta;
    x = (ListOfObjNames *) funcctx->user_fctx;

    if (funcctx->call_cntr < funcctx->max_calls) {
        HeapTuple tuple;
        Datum result;
        int idx = funcctx->call_cntr;
        
        const EVP_MD *md = EVP_get_digestbyname(x->names[idx]->name);
        long flags = EVP_MD_flags(md);

        char **values = (char **) palloc(6 * sizeof(char *));
        values[0] = pstrdup(x->names[idx]->name);
        values[1] = palloc(16);
        values[2] = palloc(16);
        values[3] = palloc(16);
        values[4] = palloc(16);
        values[5] = palloc(16);

/*
        snprintf(values[1], 16, "%d", EVP_MD_block_size(md));
        snprintf(values[2], 16, "%d", EVP_MD_size(md));
        snprintf(values[3], 16, "%d", EVP_MD_pkey_type(md));
        snprintf(values[4], 16, "%c", flags & EVP_MD_FLAG_FIPS ? 't' : 'f');
        snprintf(values[5], 16, "%d", EVP_MD_nid(md));
*/

        //values[1] = pstrdup("1");
        //values[2] = pstrdup("2");
        //values[3] = pstrdup("3");
        //values[4] = pstrdup("t");
        //values[5] = pstrdup("4");


        tuple = BuildTupleFromCStrings(attinmeta, values);
        result = HeapTupleGetDatum(tuple);

        SRF_RETURN_NEXT(funcctx, result);
    } else {
        SRF_RETURN_DONE(funcctx);
    }
}

/**
 * Return list of primary key types
 */
PG_FUNCTION_INFO_V1(pgx_openssl_list_key_types);

Datum
pgx_openssl_list_key_types(PG_FUNCTION_ARGS) {
    FuncCallContext *funcctx;
    TupleDesc tupdesc;
    AttInMetadata *attinmeta = NULL;
    ListOfObjNames *x = NULL;

    if (SRF_IS_FIRSTCALL()) {
    	MemoryContext oldContext;

        funcctx = SRF_FIRSTCALL_INIT();
        oldContext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

        // Build a tuple descriptor for our result type
        if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
             ereport(ERROR,
                 (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                  errmsg("function returning record called in context that cannot accept type record")));

        // generate attribute metadata needed later to produce tuples 
        // from raw C strings
        attinmeta = TupleDescGetAttInMetadata(tupdesc);
        funcctx->attinmeta = attinmeta;

        // get list of ciphers
        x = (ListOfObjNames *) palloc(sizeof(ListOfObjNames));
        OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_PKEY_METH, capture_obj_names, x);

		// set up function context for future calls.
        funcctx->user_fctx = x;
        funcctx->max_calls = x->cnt;

        MemoryContextSwitchTo(oldContext);
    }

    funcctx = SRF_PERCALL_SETUP();
    attinmeta = funcctx->attinmeta;
    x = (ListOfObjNames *) funcctx->user_fctx;

    if (funcctx->call_cntr < funcctx->max_calls) {
        HeapTuple tuple;
        Datum result;
        int i = funcctx->call_cntr;

        char **values = (char **) palloc(2 * sizeof(char *));
        values[0] = pstrdup(x->names[i]->name);
		values[1] = palloc(16 * sizeof(char));
		snprintf(values[1], 16, "%d", 1);
		values[2] = (x->names[i]->data == NULL) ? NULL : pstrdup(x->names[i]->data);

        tuple = BuildTupleFromCStrings(attinmeta, values);
        result = HeapTupleGetDatum(tuple);

        SRF_RETURN_NEXT(funcctx, result);
    } else {
        SRF_RETURN_DONE(funcctx);
    }
}
