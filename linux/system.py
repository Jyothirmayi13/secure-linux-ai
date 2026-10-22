import psutil
import time
from datetime import timedelta
def get_cpu_usage():
    return psutil.cpu_percent(interval=1)
def get_memory_usage():
    memory = psutil.virtual_memory()
    return memory.percent
def get_disk_usage():
    disk = psutil.disk_usage('/')
    return {
        "percent": disk.percent,
        "total": round(disk.total / (1024**3), 2),
        "free": round(disk.free / (1024**3), 2)
    }
def get_uptime():
     seconds = time.time() - psutil.boot_time()
     return str(timedelta(seconds=seconds))
def get_system_status():
    return {
        "cpu_usage": get_cpu_usage(),
        "memory_usage": get_memory_usage(),
        "disk_usage": get_disk_usage(),
        "uptime": get_uptime()
    }