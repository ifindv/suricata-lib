#include <stdio.h>
#include <sys/resource.h>

#include "suricata.h"
#include "conf-yaml-loader.h"
#include "detect-engine.h"
#include "detect-engine-tag.h"
#include "detect-parse.h"
#include "unix-manager.h"
#include "tm-threads.h"
#include "tm-queuehandlers.h"

#include "util-atomic.h"
#include "util-debug.h"
#include "util-conf.h"
#include "util-privs.h"
#include "util-signal.h"
#include "util-cpu.h"
#include "util-coredump-config.h"
#include "util-landlock.h"
#include "util-device.h"
#include "util-proto-name.h"
#include "util-misc.h"
#include "util-pidfile.h"
#include "util-var-name.h"

#include "app-layer.h"
#include "app-layer-htp.h"
#include "datasets.h"
#include "output.h"
#include "feature.h"
#include "runmodes.h"

#include "suricata-lib.h"

#ifdef __cplusplus
extern "C" {
#endif

#if 1
#define SCL_DBG(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define SCL_DBG(fmt, ...)
#endif

extern SCInstance suricata;
extern int g_detect_disabled;
extern int sc_set_caps;

extern SC_ATOMIC_DECLARE(unsigned int, engine_stage);

ThreadVars *g_lib_tv;
TmSlot *g_lib_slot;
bool g_lib_enable_ips;

char g_sc_instance_name[64];
int g_sc_instance_ready;

static void sc_instance_init(SCInstance *suri, const char *progname)
{
    memset(suri, 0x00, sizeof(*suri));

    suri->progname = progname;
    suri->run_mode = RUNMODE_UNKNOWN;

    memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
    suri->sig_file = NULL;
    suri->sig_file_exclusive = FALSE;
    suri->pid_filename = NULL;
    suri->regex_arg = NULL;

    suri->keyword_info = NULL;
    suri->runmode_custom_mode = NULL;
#ifndef OS_WIN32
    suri->user_name = NULL;
    suri->group_name = NULL;
    suri->do_setuid = FALSE;
    suri->do_setgid = FALSE;
#endif /* OS_WIN32 */
    suri->userid = 0;
    suri->groupid = 0;
    suri->delayed_detect = 0;
    suri->daemon = 0;
    suri->offline = 0;
    suri->verbose = 0;
    /* use -1 as unknown */
    suri->checksum_validation = -1;
#if HAVE_DETECT_DISABLED==1
    g_detect_disabled = suri->disabled_detect = 1;
#else
    g_detect_disabled = suri->disabled_detect = 0;
#endif
}

static TmEcode load_yaml_config(SCInstance *suri)
{
    SCEnter();

    if (suri->conf_filename == NULL)
        suri->conf_filename = DEFAULT_CONF_FILE;

    if (ConfYamlLoadFile(suri->conf_filename) != 0) {
        /* Error already displayed. */
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (suri->additional_configs) {
        for (int i = 0; suri->additional_configs[i] != NULL; i++) {
            SCLogConfig("Loading additional configuration file %s", suri->additional_configs[i]);
            ConfYamlHandleInclude(ConfGetRootNode(), suri->additional_configs[i]);
        }
    }

    SCReturnInt(TM_ECODE_OK);
}

static void setup_user_mode(SCInstance *suri)
{
    const char *log_dir = ConfigGetLogDirectory();
    int len = strlen(log_dir);
    char instance_log_dir[256] = {0};

    if (len >= 128) {
        FatalError("log directory path too long");
    }

    /* setup instance log directory log_dir/g_sc_instance_name */
    sprintf(instance_log_dir, "%s/%s", log_dir, g_sc_instance_name);
    SCL_DBG("sc instance log directory: %s\n", instance_log_dir);

    /* apply 'user mode' config updates here */
    if (suri->system == false) {
        if (suri->set_logdir == false) {
            /* override log dir to current work dir" */
            if (ConfigSetLogDirectory(instance_log_dir) != TM_ECODE_OK) {
                FatalError("could not set USER mode logdir");
            }
        }
        if (suri->set_datadir == false) {
            /* override data dir to current work dir" */
            if (ConfigSetDataDirectory(instance_log_dir) != TM_ECODE_OK) {
                FatalError("could not set USER mode datadir");
            }
        }
    }
}

static int init_run_as(SCInstance *suri)
{
#ifndef OS_WIN32
    /* Try to get user/group to run suricata as if
       command line as not decide of that */
    if (suri->do_setuid == FALSE && suri->do_setgid == FALSE) {
        const char *id;
        if (ConfGet("run-as.user", &id) == 1) {
            suri->do_setuid = TRUE;
            suri->user_name = id;
        }
        if (ConfGet("run-as.group", &id) == 1) {
            suri->do_setgid = TRUE;
            suri->group_name = id;
        }
    }
    /* Get the suricata user ID to given user ID */
    if (suri->do_setuid == TRUE) {
        if (SCGetUserID(suri->user_name, suri->group_name,
                        &suri->userid, &suri->groupid) != 0) {
            SCLogError("failed in getting user ID");
            return TM_ECODE_FAILED;
        }

        sc_set_caps = TRUE;
    /* Get the suricata group ID to given group ID */
    } else if (suri->do_setgid == TRUE) {
        if (SCGetGroupID(suri->group_name, &suri->groupid) != 0) {
            SCLogError("failed in getting group ID");
            return TM_ECODE_FAILED;
        }

        sc_set_caps = TRUE;
    }
#endif
    return TM_ECODE_OK;
}

static void sc_set_start_time(SCInstance *suri)
{
    memset(&suri->start_time, 0, sizeof(suri->start_time));
    gettimeofday(&suri->start_time, NULL);
}

static TmEcode log_version(SCInstance *suri)
{
    const char *mode = suri->system ? "SYSTEM" : "USER";
    SCLogNotice("This is %s version %s running in %s mode",
            PROG_NAME, GetProgramVersion(), mode);
    return TM_ECODE_OK;
}

static void globals_destroy(SCInstance *suri)
{
    HostShutdown();
    HTPFreeConfig();
    HTPAtExitPrintStats();

    AppLayerHtpPrintStats();

    /* TODO this can do into it's own func */
    DetectEngineCtx *de_ctx = DetectEngineGetCurrent();
    if (de_ctx) {
        DetectEngineMoveToFreeList(de_ctx);
        DetectEngineDeReference(&de_ctx);
    }
    DetectEngineClearMaster();

    AppLayerDeSetup();
    DatasetsSave();
    DatasetsDestroy();
    TagDestroyCtx();

    LiveDeviceListClean();
    OutputDeregisterAll();
    FeatureTrackingRelease();
    SCProtoNameRelease();
    TimeDeinit();
    TmqhCleanup();
    TmModuleRunDeInit();
    ParseSizeDeinit();

#ifdef HAVE_DPDK
    DPDKCleanupEAL();
#endif

#ifdef HAVE_AF_PACKET
    AFPPeersListClean();
#endif

#ifdef NFQ
    NFQContextsClean();
#endif

#ifdef BUILD_HYPERSCAN
    MpmHSGlobalCleanup();
#endif

    ConfDeInit();
#ifdef HAVE_LUAJIT
    LuajitFreeStatesPool();
#endif
    DetectParseFreeRegexes();

    SCPidfileRemove(suri->pid_filename);
    SCFree(suri->pid_filename);
    suri->pid_filename = NULL;

    VarNameStoreDestroy();
    SCLogDeInitLogModule();
}
 
static int run_mode_library_workers(void)
{
    SCEnter();

    SCL_DBG("== run mode library workers\n");

    ThreadVars *tv = NULL;
    TmModule *tm_module = NULL;
 
    pthread_t tid = pthread_self();
    const char *tname = "LW";

    SCL_DBG("thread id %lu, name %s\n", tid, tname);
 
    tv = TmThreadCreatePacketHandler(
        tname,
        "packetpool", "packetpool",
        "packetpool", "packetpool",
        "pktacqloop"
        );
    if (!tv) {
        SCLogError("TmThreadsCreatePacketHandler failed for %s", tname);
        SCReturnInt(-1);
    }
    tv->t = tid;

    SCL_DBG("tm thread create packet handler tv %p\n", tv);

    /**
     * add recv module (do nothing actually, all packet deliver in suricata_proc())
     */
    tm_module = TmModuleGetByName("LibraryRecv");
    if (tm_module == NULL) {
        SCLogError("TmModuleGetByName failed for LibraryRecv");
        SCReturnInt(-1);
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    SCL_DBG("tm slot set func append library recv module %p\n", tm_module);

    /**
     * add decode module
     */
    tm_module = TmModuleGetByName("LibraryDecode");
    if (tm_module == NULL) {
        SCLogError("TmModuleGetByName failed for LibraryDecode");
        SCReturnInt(-1);
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    SCL_DBG("tm slot set func append decode dpdk module %p\n", tm_module);

    /** 
     * it's nesessary to set the flow worker module cause detect and logger inside it
     */
    tm_module = TmModuleGetByName("FlowWorker");
    if (tm_module == NULL) {
        SCLogError("TmModuleGetByName failed for FlowWorker");
        SCReturnInt(-1);
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    SCL_DBG("tm slot set func append flow worker module %p\n", tm_module);

    g_lib_tv = tv;
    g_lib_slot = tv->tm_slots;
    TmThreadAppend(tv, tv->type);

    SCL_DBG("tm thread append tv type %d\n", tv->type);

    /**
     * initialize all modules for the thread
     */
    tv->tm_func(tv);

    SCReturnInt(0);
}

static void run_mode_library_enable_ips(void)
{
    SCEnter();
    SCL_DBG("== run mode library enable ips\n");

    if (g_lib_enable_ips) {
        SCLogInfo("run mode library enable ips");
        EngineModeSetIPS();
    }

    SCReturn;
}

static void run_mode_library_register(void)
{
    SCEnter();
    SCL_DBG("== run mode library register\n");

    RunModeRegisterNewRunMode(
        RUNMODE_LIBRARY, 
        "workers",
        "Workers library mode, each thread does all tasks from acquisition to logging",
        run_mode_library_workers,
        run_mode_library_enable_ips
        );

	SCReturn;
}

static TmEcode library_recv_thread_init(ThreadVars *t, const void *initdata, void **data)
{
    SCEnter();
    SCLogInfo("library recv thread init");
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode library_recv_pkt_acq_loop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();
    SCLogInfo("library recv pkt acq loop");
    SCReturnInt(TM_ECODE_OK);
}
 
static void tm_module_library_recv_register(void)
{
	SCEnter();
    SCL_DBG("== tm module library recv register\n");
 
	tmm_modules[TMM_RECEIVELIBRARY].name = "LibraryRecv";
	tmm_modules[TMM_RECEIVELIBRARY].ThreadInit = library_recv_thread_init;
	tmm_modules[TMM_RECEIVELIBRARY].Func = NULL;
    tmm_modules[TMM_RECEIVELIBRARY].PktAcqLoop = library_recv_pkt_acq_loop;
	tmm_modules[TMM_RECEIVELIBRARY].ThreadExitPrintStats = NULL;
	tmm_modules[TMM_RECEIVELIBRARY].ThreadDeinit = NULL;
	tmm_modules[TMM_RECEIVELIBRARY].cap_flags = 0;
	tmm_modules[TMM_RECEIVELIBRARY].flags = TM_FLAG_RECEIVE_TM;
 
	SCReturn;
}

static TmEcode library_decode_thread_init(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode library_decode(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    BUG_ON(PKT_IS_PSEUDOPKT(p));

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    /* If suri has set vlan during reading, we increase vlan counter */
    if (p->vlan_idx) {
        StatsIncr(tv, dtv->counter_vlan);
    }

    /* call the decoder */
    DecodeLinkLayer(tv, dtv, p->datalink, p, GET_PKT_DATA(p), GET_PKT_LEN(p));

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode library_decode_thread_deinit(ThreadVars *tv, void *data)
{
    SCEnter();
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

static void tm_module_library_decode_register(void)
{
    tmm_modules[TMM_DECODELIBRARY].name = "LibraryDecode";
    tmm_modules[TMM_DECODELIBRARY].ThreadInit = library_decode_thread_init;
    tmm_modules[TMM_DECODELIBRARY].Func = library_decode;
    tmm_modules[TMM_DECODELIBRARY].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODELIBRARY].ThreadDeinit = library_decode_thread_deinit;
    tmm_modules[TMM_DECODELIBRARY].cap_flags = 0;
    tmm_modules[TMM_DECODELIBRARY].flags = TM_FLAG_DECODE_TM;
}

static int suricata_pub_init(bool ips)
{
	SCEnter();
    SCLogInfo("suricata pub init");

    SCL_DBG("== suricata pub init\n");

    sc_instance_init(&suricata, "suricata");
    g_lib_enable_ips = ips;

    SCL_DBG("sc instance init\n");

    if (InitGlobal() != 0) {
        exit(EXIT_FAILURE);
    }

    SCL_DBG("init global\n");

    run_mode_library_register();

    SCL_DBG("run mode library register\n");

    // #ifdef OS_WIN32
    //     /* service initialization */
    //     if (WindowsInitService(argc, argv) != 0) {
    //         exit(EXIT_FAILURE);
    //     }
    // #endif /* OS_WIN32 */

    // if (ParseCommandLine(argc, argv, &suricata) != TM_ECODE_OK) {
    //     exit(EXIT_FAILURE);
    // }

    // if (FinalizeRunMode(&suricata, argv) != TM_ECODE_OK) {
    //     exit(EXIT_FAILURE);
    // }

    // switch (StartInternalRunMode(&suricata, argc, argv)) {
    //     case TM_ECODE_DONE:
    //         exit(EXIT_SUCCESS);
    //     case TM_ECODE_FAILED:
    //         exit(EXIT_FAILURE);
    // }

    suricata.run_mode = RUNMODE_LIBRARY;

    /* Initializations for global vars, queues, etc (memsets, mutex init..) */
    GlobalsInitPreConfig();

    SCL_DBG("globals init pre config\n");

    /* Load yaml configuration file if provided. */
    if (load_yaml_config(&suricata) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    SCL_DBG("load yaml config\n");

    // if (suricata.run_mode == RUNMODE_DUMP_CONFIG) {
    //     ConfDump();
    //     exit(EXIT_SUCCESS);
    // }

    // int tracking = 1;
    // if (ConfGetBool("vlan.use-for-tracking", &tracking) == 1 && !tracking) {
    //     /* Ignore vlan_ids when comparing flows. */
    //     g_vlan_mask = 0x0000;
    // }
    // SCLogDebug("vlan tracking is %s", tracking == 1 ? "enabled" : "disabled");
    // if (ConfGetBool("livedev.use-for-tracking", &tracking) == 1 && !tracking) {
    //     /* Ignore livedev id when comparing flows. */
    //     g_livedev_mask = 0x0000;
    // }
    setup_user_mode(&suricata);
    
    SCL_DBG("setup user mode\n");

    init_run_as(&suricata);
    
    SCL_DBG("init run as\n");

    /* Since our config is now loaded we can finish configurating the
     * logging module. */
    SCLogLoadConfig(suricata.daemon, suricata.verbose, suricata.userid, suricata.groupid);

    SCL_DBG("sc log load config\n");

    log_version(&suricata);

    SCL_DBG("log version\n");

    UtilCpuPrintSummary();

    SCL_DBG("util cpu print summary\n");

    // RunModeInitializeThreadSettings();

    // if (suricata.run_mode == RUNMODE_CONF_TEST)
    //     SCLogInfo("Running suricata under test mode");

    // if (ParseInterfacesList(suricata.aux_run_mode, suricata.pcap_dev) != TM_ECODE_OK) {
    //     exit(EXIT_FAILURE);
    // }

    if (PostConfLoadedSetup(&suricata) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    SCL_DBG("post conf loaded setup\n");

    tm_module_library_recv_register();
    tm_module_library_decode_register();

    SCL_DBG("tm module library recv register\n");

    SCDropMainThreadCaps(suricata.userid, suricata.groupid);

    SCL_DBG("sc drop main thread caps\n");

    /* Re-enable coredumps after privileges are dropped. */
    CoredumpEnable();

    SCL_DBG("coredump enable\n");

    if (suricata.run_mode != RUNMODE_UNIX_SOCKET && !suricata.disabled_detect) {
        suricata.unix_socket_enabled = ConfUnixSocketIsEnable();
    }

    PreRunPostPrivsDropInit(suricata.run_mode);

    SCL_DBG("pre run post privs drop init\n");

    LandlockSandboxing(&suricata);

    SCL_DBG("landlock sandboxing\n");

    PostConfLoadedDetectSetup(&suricata);
    // if (suricata.run_mode == RUNMODE_ENGINE_ANALYSIS) {
    //     goto out;
    // } else if (suricata.run_mode == RUNMODE_CONF_TEST){
    //     SCLogNotice("Configuration provided was successfully loaded. Exiting.");
    //     goto out;
    // } else if (suricata.run_mode == RUNMODE_DUMP_FEATURES) {
    //     FeatureDump();
    //     goto out;
    // }

    SCL_DBG("post conf loaded detect setup\n");

    sc_set_start_time(&suricata);

    SCL_DBG("sc set start time\n");

    RunModeDispatch(suricata.run_mode, suricata.runmode_custom_mode,
            suricata.capture_plugin_name, suricata.capture_plugin_args);
    if (suricata.run_mode != RUNMODE_UNIX_SOCKET) {
        UnixManagerThreadSpawnNonRunmode(suricata.unix_socket_enabled);
    }

    SCL_DBG("run mode dispatch\n");

    /* Wait till all the threads have been initialized */
    // if (TmThreadWaitOnThreadInit() == TM_ECODE_FAILED) {
    //     FatalError("Engine initialization failed, "
    //                "aborting...");
    // }

    int limit_nproc = 0;
    if (ConfGetBool("security.limit-noproc", &limit_nproc) == 0) {
        limit_nproc = 0;
    }

#if defined(SC_ADDRESS_SANITIZER)
    if (limit_nproc) {
        SCLogWarning(
                "\"security.limit-noproc\" (setrlimit()) not set when using address sanitizer");
        limit_nproc = 0;
    }
#endif

    if (limit_nproc) {
#if defined(HAVE_SYS_RESOURCE_H)
#ifdef linux
        if (geteuid() == 0) {
            SCLogWarning("setrlimit has no effet when running as root.");
        }
#endif
        struct rlimit r = { 0, 0 };
        if (setrlimit(RLIMIT_NPROC, &r) != 0) {
            SCLogWarning("setrlimit failed to prevent process creation.");
        }
#else
        SCLogWarning("setrlimit unavailable.");
#endif
    }

    SC_ATOMIC_SET(engine_stage, SURICATA_RUNTIME);
    PacketPoolPostRunmodes();

    SCL_DBG("packet pool post runmodes\n");

    /* Un-pause all the paused threads */
    TmThreadContinueThreads();

    SCL_DBG("tm thread continue threads\n");

    /* Must ensure all threads are fully operational before continuing with init process */
    // if (TmThreadWaitOnThreadRunning() != TM_ECODE_OK) {
    //     exit(EXIT_FAILURE);
    // }

    // SCL_DBG("tm thread wait on thread running\n");

    /* Print notice and send OS specific notification of threads in running state */
    // OnNotifyRunning();

    // PostRunStartedDetectSetup(&suricata);
    
    // DPDKEvaluateHugepages();

    SCPledge();

    SCL_DBG("sc pledge\n");

    // SuricataMainLoop(&suricata);

    /* Update the engine stage/status flag */
    SC_ATOMIC_SET(engine_stage, SURICATA_DEINIT);

    // UnixSocketKillSocketThread();
    // PostRunDeinit(suricata.run_mode, &suricata.start_time);
    /* kill remaining threads */
    // TmThreadKillThreads();

// out:
    // GlobalsDestroy(&suricata);

    // exit(EXIT_SUCCESS);
    SCReturnInt(0);
}

static int suricata_pri_init(void)
{
    SCEnter();
    SCLogInfo("suricata pri init");
    g_sc_instance_ready = 1;
    SCReturnInt(0);
}

int suricata_init(const char *name, bool ips)
{
    strlcpy(g_sc_instance_name, name, 64);
    int rv = suricata_pub_init(ips);
    if (rv) {
        return rv;
    }
    return suricata_pri_init();
}

int suricata_proc(void *pkt, int len, void *res)
{
    Packet *p = PacketGetFromAlloc();
    SET_PKT_LEN(p, (size_t)len);
    p->ext_pkt = pkt;
    p->datalink = 1;

    if (TmThreadsSlotVarRun(g_lib_tv, p, g_lib_slot) != TM_ECODE_OK) {
        p->ext_pkt = NULL;
        PacketFreeOrRelease(p);
        SCLogError("suricata proc pkt failed");
        return -1;
    }
    p->ext_pkt = NULL;
    PacketFreeOrRelease(p);
    return 0;
}

int suricata_load(void)
{
    // if (sigterm_count || sigint_count) {
    //     suricata_ctl_flags |= SURICATA_STOP;
    // }

    // if (suricata_ctl_flags & SURICATA_STOP) {
    //     SCLogNotice("Signal Received.  Stopping engine.");
    //     break;
    // }

    // TmThreadCheckThreadState();

    // if (sighup_count > 0) {
    //     OutputNotifyFileRotation();
    //     sighup_count--;
    // }
    if (!g_sc_instance_ready) {
        return -1;
    }

    if (!(DetectEngineReloadIsStart())) {
        DetectEngineReloadStart();
        DetectEngineReload(&suricata);
        DetectEngineReloadSetIdle();
    } else {
        DetectEngineReload(&suricata);
        DetectEngineReloadSetIdle();
    }

    return 0;
}

int suricata_exit(void)
{
    /* Update the engine stage/status flag */
    SC_ATOMIC_SET(engine_stage, SURICATA_DEINIT);

    UnixSocketKillSocketThread();
    PostRunDeinit(suricata.run_mode, &suricata.start_time);
    
    /* kill remaining threads */
    TmThreadKillThreads();
    globals_destroy(&suricata);

    return 0;
}

#ifdef __cplusplus
}
#endif
