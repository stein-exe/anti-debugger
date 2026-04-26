def anti_debugger(raw_code):
    anti_debug_code =r'''
import threading
import time
import os
import platform
import gc
class _Config:
    ENABLED = True
    BASE_INTERVAL = 5
    CACHE_TTL = 30
    MAX_INTERVAL = 30
    MIN_INTERVAL = 1
    AGGRESSIVE_MODE = False
    GC_INTERVAL = 60

_KEYWORDS = frozenset({
    'fiddler', 'wireshark', 'dnspy', 'httpdebuggerui', 'x32dbg', 'x64dbg',
    'dotnetreactor', 'httpdebuggersvc', 'httptoolkit', 'ida', 'scylla',
    'idag', 'scyllax64', 'scyllahide', 'scyllax64hide', 'scyllax86',
    'scyllax86hide', 'immunitydebugger', 'megadumper', 'debug', 'imdmp',
    'graywolf', 'packets', 'analyzing', 'debugging', 'procdump', 'netchk',
    'netlim', 'sandbox', 'ollydbg', 'ollyice', 'titanhide', 'reclass',
    'phantom', 'idapro', 'hwinfo', 'enigmaprotector', 'debugshield',
    'codevirtualizer', 'idatools', 'ollydumpex', 'ollyheaptrace', 'peid',
    'pescrambler', 'pesieve', 'scyllahide', 'pebear', 'peinfo',
    'pestudio', 'peview', 'protectionid', 'studpe', 'rdgpackerdetector',
    'limecrypt', 'sysinternals', 'sysanalyzer', 'idapython', 'pedumper',
    'pedump', 'peinspector', 'scyllassa', 'dumpme', 'idapro', 'gdb',
    'strace', 'ltrace', 'valgrind', 'radare2', 'rr', 'lsof'
})

_WHITELIST = frozenset({
    'system', 'svchost', 'explorer', 'bash', 'sh', 'python', 'python3',
    'systemd', 'init', 'kernel', 'kthreadd'
})

_PROCESS_CACHE = frozenset()
_LAST_CACHE_UPDATE = 0
_SYSTEM = platform.system().lower()

_NORM_TABLE = str.maketrans('', '', ' .-_')


def _normalize(name):
    """Ultra-fast normalization with fixed .exe handling"""
    if not name:
        return ""
    normalized = name.lower().translate(_NORM_TABLE)
    if normalized.endswith("exe"):
        normalized = normalized[:-3]
    return normalized


def _validate_config():
    """Validate configuration settings"""
    if _Config.BASE_INTERVAL < 0.1:
        _Config.BASE_INTERVAL = 1
    if _Config.CACHE_TTL < 1:
        _Config.CACHE_TTL = 10
    if _Config.MAX_INTERVAL < _Config.BASE_INTERVAL:
        _Config.MAX_INTERVAL = _Config.BASE_INTERVAL * 3


def _should_skip_check():
    """Skip check if system is under high load"""
    try:
        if _SYSTEM == "linux":
            with open('/proc/loadavg', 'r') as f:
                load = float(f.read().split()[0])
                return load > 2.0
    except Exception:
        pass
    return False


def _get_windows_process_names():
    """Get Windows process names efficiently"""
    processes = set()
    try:
        import subprocess
        result = subprocess.run(
            ['tasklist', '/NH', '/FO', 'CSV'],
            capture_output=True,
            text=True,
            timeout=2,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
        )
        
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if not line:
                    continue
                parts = line.split(',', 1)
                if parts:
                    name = parts[0].strip('"')
                    if name:
                        normalized = _normalize(name)
                        if normalized and normalized not in _WHITELIST:
                            processes.add(normalized)
    except Exception:
        pass
    return frozenset(processes)


def _get_linux_process_names():
    """Get Linux process names efficiently"""
    processes = set()
    try:
        import subprocess
        result = subprocess.run(
            ['ps', '-eo', 'comm', '--no-headers'],
            capture_output=True,
            text=True,
            timeout=2
        )
        if result.returncode == 0:
            for name in result.stdout.splitlines():
                name = name.strip()
                if name:
                    normalized = _normalize(name)
                    if normalized and normalized not in _WHITELIST:
                        processes.add(normalized)
            return frozenset(processes)
    except Exception:
        pass
    
    try:
        for entry in os.listdir('/proc'):
            if not entry.isdigit():
                continue
            try:
                with open(f'/proc/{entry}/comm', 'r') as f:
                    name = f.read().strip()
                    if name:
                        normalized = _normalize(name)
                        if normalized and normalized not in _WHITELIST:
                            processes.add(normalized)
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
    except Exception:
        pass
    
    return frozenset(processes)


def _get_process_names():
    """Get process names with intelligent caching and rate limiting"""
    global _LAST_CACHE_UPDATE, _PROCESS_CACHE
    
    current_time = time.time()
    
    if current_time - _LAST_CACHE_UPDATE < _Config.CACHE_TTL:
        return _PROCESS_CACHE
    
    if current_time - _LAST_CACHE_UPDATE < 1:
        return _PROCESS_CACHE
    
    if _SYSTEM == "windows":
        new_cache = _get_windows_process_names()
    elif _SYSTEM == "linux":
        new_cache = _get_linux_process_names()
    else:
        new_cache = frozenset()
    
    _PROCESS_CACHE = new_cache
    _LAST_CACHE_UPDATE = current_time
    return new_cache


def _check_tracer_linux():
    """Check if process is being traced on Linux"""
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("TracerPid:"):
                    tracer_pid = int(line.split()[1])
                    return tracer_pid != 0
    except Exception:
        pass
    return False


def _safe_exit():
    """Graceful exit with fallback"""
    try:
        os._exit(1)
    except Exception:
        try:
            import signal
            os.kill(os.getpid(), signal.SIGTERM)
        except Exception:
            pass


def _anti_debugger_thread():
    """Main protection thread with adaptive intervals and optimizations"""
    consecutive_clean_checks = 0
    check_times = []
    
    while True:
        start_time = time.time()
        detected = False
        
        try:
            if _should_skip_check():
                time.sleep(_Config.MAX_INTERVAL)
                continue
            
            if not _KEYWORDS:
                time.sleep(_Config.MAX_INTERVAL)
                continue
            
            current_processes = _get_process_names()
            
            if not current_processes:
                consecutive_clean_checks += 1
                time.sleep(_Config.BASE_INTERVAL)
                continue
            
            detected = bool(_KEYWORDS & current_processes)
            
            if _SYSTEM == "linux" and not detected:
                detected = _check_tracer_linux()
            
            if detected:
                _safe_exit()
            else:
                consecutive_clean_checks += 1
                
        except Exception:
            consecutive_clean_checks += 1
        
        check_duration = time.time() - start_time
        check_times.append(check_duration)
        if len(check_times) > 20:
            check_times.pop(0)
        
        if _Config.AGGRESSIVE_MODE:
            sleep_time = _Config.MIN_INTERVAL
        elif consecutive_clean_checks > 10:
            sleep_time = min(_Config.BASE_INTERVAL * 2, _Config.MAX_INTERVAL)
        else:
            sleep_time = _Config.BASE_INTERVAL
        
        if len(check_times) >= 10:
            avg_duration = sum(check_times) / len(check_times)
            if avg_duration > 1.0:
                sleep_time = min(sleep_time + 1, _Config.MAX_INTERVAL)
        
        time.sleep(sleep_time)


def _periodic_gc():
    """Periodic garbage collection to reduce memory footprint"""
    while True:
        time.sleep(_Config.GC_INTERVAL)
        gc.collect()


def _start_protection():
    """Initialize and start anti-debugger protection"""
    if not _Config.ENABLED:
        return
    
    _validate_config()
    
    time.sleep(0.5)
    

    protection_thread = threading.Thread(
        target=_anti_debugger_thread,
        daemon=True,
        name="AntiDebug"
    )
    protection_thread.start()
    

    gc_thread = threading.Thread(
        target=_periodic_gc,
        daemon=True,
        name="GC"
    )
    gc_thread.start()



_start_protection()



'''

    return anti_debug_code.strip() + "\n\n" + raw_code.strip()
