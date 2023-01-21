// My tracer

#include <stdio.h>
#include <stddef.h> /* for offsetof */
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "utils.h"

#define MODULE2TRACE "mymodule.dll"
#define NOSHOWRESULTS
#ifdef SHOWRESULTS
#undef SHOWRESULTS
#endif

/* Each ins_ref_t describes an executed instruction. */
typedef struct _ins_ref_t {
    app_pc pc;
    int opcode;
} ins_ref_t;

/* Max number of ins_ref a buffer can have. It should be big enough
 * to hold all entries between clean calls.
 */
#define MAX_NUM_INS_REFS 8192
/* The maximum size of buffer for holding ins_refs. */
#define MEM_BUF_SIZE (sizeof(ins_ref_t) * MAX_NUM_INS_REFS)

/* thread private log file and counter */
typedef struct {
    byte *seg_base;
    ins_ref_t *buf_base;
    file_t log;
    FILE *logf;
    uint64 num_refs;
} per_thread_t;

static bool widevine_loaded = false;
static app_pc dllstart;
static client_id_t client_id;
static void *mutex;     /* for multithread support */
static uint64 num_refs; /* keep a global instruction reference count */

/* Allocated TLS slot offsets */
enum {
    INSTRACE_TLS_OFFS_BUF_PTR,
    INSTRACE_TLS_COUNT, /* total number of TLS slots allocated */
};
static reg_id_t tls_seg;
static uint tls_offs;
static int tls_idx;
#define TLS_SLOT(tls_base, enum_val) (void **)((byte *)(tls_base) + tls_offs + (enum_val))
#define BUF_PTR(tls_base) *(ins_ref_t **)TLS_SLOT(tls_base, INSTRACE_TLS_OFFS_BUF_PTR)

#define MINSERT instrlist_meta_preinsert


static void
event_thread_init(void *drcontext)
{
    per_thread_t *data = dr_thread_alloc(drcontext, sizeof(per_thread_t));
    DR_ASSERT(data != NULL);
    drmgr_set_tls_field(drcontext, tls_idx, data);

    /* Keep seg_base in a per-thread data structure so we can get the TLS
     * slot and find where the pointer points to in the buffer.
     */
    data->seg_base = dr_get_dr_segment_base(tls_seg);
    data->buf_base =
        dr_raw_mem_alloc(MEM_BUF_SIZE, DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
    DR_ASSERT(data->seg_base != NULL && data->buf_base != NULL);
    /* put buf_base to TLS as starting buf_ptr */
    BUF_PTR(data->seg_base) = data->buf_base;

    data->num_refs = 0;

}

static void
event_thread_exit(void* drcontext)
{
    per_thread_t* data;
    // instrace(drcontext); /* dump any remaining buffer entries */
    data = drmgr_get_tls_field(drcontext, tls_idx);
    dr_mutex_lock(mutex);
    num_refs += data->num_refs;
    dr_mutex_unlock(mutex);
    if (data->logf != NULL)
    {
        log_stream_close(data->logf); /* closes fd too */
    }
    dr_raw_mem_free(data->buf_base, MEM_BUF_SIZE);
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

static dr_emit_flags_t
event_bb(void* drcontext, void* tag, instrlist_t* bb, bool for_trace, bool translating, OUT void** user_data)
{
    per_thread_t* data;
    ins_ref_t* ins_ref, * buf_ptr;

    data = drmgr_get_tls_field(drcontext, tls_idx);
    ins_ref = (ins_ref_t*)data->buf_base;
    //ins_ref = (ins_ref_t*) bb;

    /* we don't want to auto-predicate any instrumentation */
    drmgr_disable_auto_predication(drcontext, bb);
    //ptr_uint_t pc = ins_ref->pc;
    //fprintf(data->logf, "Opcode: %xl\n", ins_ref->opcode);

    app_pc pc = dr_fragment_app_pc(tag);
    if (pc != NULL)
    {
        module_data_t* module_data = dr_lookup_module(pc);
        if (module_data != NULL)
        {
            module_names_t module_names = module_data->names;
            if (strlen(module_names.file_name) > 0)
            {

                if (strncmp(module_names.file_name, MODULE2TRACE, strlen(MODULE2TRACE)) == 0)
                {

                    if (data->logf == NULL)
                    {
                        data->log =
                            log_file_open(client_id, drcontext, NULL, "instrace",
#ifndef WINDOWS
                                DR_FILE_CLOSE_ON_FORK |
#endif
                                DR_FILE_ALLOW_LARGE);
                        data->logf = log_stream_from_file(data->log);
                    }


                    buf_ptr = BUF_PTR(data->seg_base);
                    //fprintf(data->logf, PIFX "\n", pc);
                    fprintf(data->logf, "MODULE2TRACE+%x\n", pc - dllstart);
                    BUF_PTR(data->seg_base) = data->buf_base;
                }
            }
        }
    }
    return DR_EMIT_DEFAULT;
}

static void
event_module_load(void* drcontext, const module_data_t* info, bool loaded)
{
    per_thread_t* data;
    data = drmgr_get_tls_field(drcontext, tls_idx);

    const char* prefname = dr_module_preferred_name(info);
    //dr_messagebox(prefname);

    if (strncmp(prefname, MODULE2TRACE, strlen(MODULE2TRACE)) == 0)
    {
        widevine_loaded = true;
        if (data->logf == NULL)
        {
            data->log =
                log_file_open(client_id, drcontext, NULL, "instrace",
#ifndef WINDOWS
                    DR_FILE_CLOSE_ON_FORK |
#endif
                    DR_FILE_ALLOW_LARGE);
            data->logf = log_stream_from_file(data->log);
        }
        dllstart = info->start;
        fprintf(data->logf, ";MODULE2TRACE loaded into process at " PIFX "\n", info->start);

       
    }
}

static void
event_exit(void)
{
    dr_log(NULL, DR_LOG_ALL, 1, "Client 'instrace' num refs seen: " SZFMT "\n", num_refs);
    if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT))
        DR_ASSERT(false);

    if (!drmgr_unregister_tls_field(tls_idx) ||
        !drmgr_unregister_thread_init_event(event_thread_init) ||
        !drmgr_unregister_thread_exit_event(event_thread_exit) ||
        !drmgr_unregister_bb_instrumentation_event(event_bb) ||
        drreg_exit() != DRREG_SUCCESS)
        DR_ASSERT(false);

    dr_mutex_destroy(mutex);
    drmgr_exit();
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{

    /* We need 2 reg slots beyond drreg's eflags slots => 3 slots */
    drreg_options_t ops = { sizeof(ops), 3, false };
    dr_set_client_name("DynamoRIO Sample Client 'instrace' for widevine",
                       "http://dynamorio.org/issues");
    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS)
        DR_ASSERT(false);

    /* register events */

    if (!drmgr_register_module_load_event(event_module_load) ||
        !drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_thread_exit_event(event_thread_exit) ||
        !drmgr_register_bb_instrumentation_event(event_bb, NULL, NULL))
        DR_ASSERT(false);

    dr_register_exit_event(event_exit);

    client_id = id;
    mutex = dr_mutex_create();

    tls_idx = drmgr_register_tls_field();
    DR_ASSERT(tls_idx != -1);
    /* The TLS field provided by DR cannot be directly accessed from the code cache.
     * For better performance, we allocate raw TLS so that we can directly
     * access and update it with a single instruction.
     */
    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0))
        DR_ASSERT(false);

    dr_log(NULL, DR_LOG_ALL, 1, "Client 'instrace' initializing\n");
}