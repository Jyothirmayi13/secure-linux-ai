import psutil
import time


def get_top_cpu_processes(limit=5):
    processes = []

    # First measurement
    for process in psutil.process_iter(["pid", "name"]):
        try:
            process.cpu_percent()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Give psutil time to measure
    time.sleep(1)

    # Second measurement
    for process in psutil.process_iter(["pid", "name"]):
        try:
            cpu = process.cpu_percent()

            processes.append({
                "pid": process.info["pid"],
                "name": process.info["name"],
                "cpu_percent": cpu
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    processes.sort(
        key=lambda process: process["cpu_percent"],
        reverse=True
    )

    return processes[:limit]
def get_top_memory_processes(limit=5):
    processes = []

    for process in psutil.process_iter(
        ["pid", "name", "memory_percent"]
    ):
        try:
            processes.append({
                "pid": process.info["pid"],
                "name": process.info["name"],
                "memory_percent": process.info["memory_percent"]
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    processes.sort(
        key=lambda process: process["memory_percent"],
        reverse=True
    )

    return processes[:limit]
