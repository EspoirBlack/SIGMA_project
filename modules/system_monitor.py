"""
System Monitor Module - Enhanced Version
Collects detailed system information
"""
import psutil
import socket
import time
from datetime import datetime
import logging
import pythoncom
import wmi
import win32com
import winreg
import win32net
import subprocess
import json

class SystemMonitor:
    def __init__(self):
        self.process_cache = []
        self.connection_cache = []
        logging.basicConfig(level=logging.INFO)
    
    def get_usb_devices(self):
        """
        Return a set of device IDs for currently connected USB devices using WMI.
        This method properly initializes COM for the calling thread.
        """
        pythoncom.CoInitialize()   # Initialize COM for this thread
        try:
            c = wmi.WMI()
            usb_ids = set()
            for device in c.Win32_PnPEntity(ConfigManagerErrorCode=0):
                # Look for USB in the name, description, or PNPClass
                if (device.Name and 'USB' in device.Name) or \
                (device.Description and 'USB' in device.Description) or \
                (device.PNPClass and 'usb' in device.PNPClass.lower()):
                    usb_ids.add(device.DeviceID)
            return usb_ids
        except Exception as e:
            print(f"[WMI] Error getting USB devices: {e}")
            return set()
        finally:
            pythoncom.CoUninitialize()   # Clean up COM for this thread
    
    def get_scheduled_tasks(self):
        """Returns a set of paths of all scheduled tasks on the system."""
        import pythoncom
        import win32com.client
        pythoncom.CoInitialize()
        try:
            scheduler = win32com.client.Dispatch('Schedule.Service')
            scheduler.Connect()
            task_names = set()
            folders = [scheduler.GetFolder('\\')]
            while folders:
                folder = folders.pop(0)
                # add subfolders
                folders.extend(list(folder.GetFolders(0)))
                # get tasks in current folder
                tasks = list(folder.GetTasks(0))
                for task in tasks:
                    task_names.add(task.Path)
            return task_names
        except Exception as e:
            print(f"[Scheduled Tasks] Error retrieving tasks: {e}")
            return set()
        finally:
            pythoncom.CoUninitialize()

    def get_registry_snapshot(self):
        """
        Returns a dictionary of critical registry key values for persistence detection.
        Keys monitored:
        - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
        - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon (Shell, Userinit)
        """
        snapshot = {}
        
        # Define registry paths to monitor
        paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
        ]
        
        for hive, subkey in paths:
            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        snapshot[f"{subkey}\\{name}"] = value
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception as e:
                # Key may not exist; ignore
                pass
        
        return snapshot
        
    def get_processes(self):
        #Get detailed running processes
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username', 'exe', 'create_time']):
                try:
                    pinfo = proc.info
                    
                    # Get parent process
                    try:
                        parent = proc.parent()
                        parent_name = parent.name() if parent else None
                        parent_pid = parent.pid if parent else None
                    except:
                        parent_name = None
                        parent_pid = None
                    
                    # Get CPU times
                    try:
                        cpu_times = proc.cpu_times()
                        cpu_user = float(cpu_times.user) if cpu_times.user else 0.0
                        cpu_system = float(cpu_times.system) if cpu_times.system else 0.0
                    except:
                        cpu_user = 0.0
                        cpu_system = 0.0
                    
                    # CPU percent
                    cpu_percent = pinfo.get('cpu_percent', 0) or 0
                    memory_percent = pinfo.get('memory_percent', 0) or 0
                    
                    # Calculate memory in MB
                    try:
                        total_memory = psutil.virtual_memory().total
                        memory_mb = (memory_percent / 100) * (total_memory / (1024 * 1024))
                    except:
                        memory_mb = 0.0
                    
                    process_entry = {
                        'pid': int(pinfo['pid']),
                        'name': str(pinfo.get('name', 'Unknown')),
                        'exe': str(pinfo.get('exe', 'Unknown')),
                        'cpu_percent': round(float(cpu_percent), 2),
                        'memory_percent': round(float(memory_percent), 2),
                        'memory_mb': round(memory_mb, 2),
                        'username': str(pinfo.get('username', 'Unknown')),
                        'parent_name': str(parent_name) if parent_name else 'None',
                        'parent_pid': int(parent_pid) if parent_pid else None,
                        'cpu_user': round(cpu_user, 2),
                        'cpu_system': round(cpu_system, 2),
                        'create_time': datetime.fromtimestamp(pinfo['create_time']).isoformat() if pinfo['create_time'] else 'Unknown',
                        'timestamp': datetime.now().isoformat()
                    }
                    processes.append(process_entry)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception:
                    continue
                    
        except Exception as e:
            logging.error(f"Error getting processes: {str(e)}")
            return []
        
        if processes:
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        
        return processes
    
    def get_local_users(self):
        """
        Returns a set of usernames of all local user accounts on the system.
        """
        try:
            users = set()
            # Query local users (level 0 returns just the username)
            resume = 0
            while True:
                data, total, resume = win32net.NetUserEnum(None, 0, 0, resume)
                for user in data:
                    users.add(user['name'])
                if resume == 0:
                    break
            return users
        except Exception as e:
            print(f"[User Accounts] Error enumerating users: {e}")
            return set()
    
    def get_network_connections(self):
        """Get active network connections"""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    if not conn.laddr:
                        continue
                    
                    local_ip = conn.laddr.ip
                    local_port = conn.laddr.port
                    
                    remote_ip = None
                    remote_port = None
                    if conn.raddr:
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port
                    
                    process_name = 'Unknown'
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            process_name = proc.name()
                        except:
                            pass
                    
                    connection = {
                        'process': process_name,
                        'pid': conn.pid,
                        'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                        'family': 'IPv4' if conn.family == socket.AF_INET else 'IPv6',
                        'local_ip': local_ip,
                        'local_port': local_port,
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'status': conn.status,
                        'timestamp': datetime.now().isoformat()
                    }
                    connections.append(connection)
                    
                except Exception:
                    continue
                    
        except Exception as e:
            logging.error(f"Error getting connections: {str(e)}")
        
        return connections
    
    def get_connection_stats(self):
        """Get connection statistics"""
        connections = self.get_network_connections()
        
        stats = {
            'total': len(connections),
            'established': len([c for c in connections if c.get('status') == 'ESTABLISHED']),
            'listening': len([c for c in connections if c.get('status') == 'LISTEN']),
            'time_wait': len([c for c in connections if c.get('status') == 'TIME_WAIT']),
            'by_protocol': {
                'TCP': len([c for c in connections if c.get('type') == 'TCP']),
                'UDP': len([c for c in connections if c.get('type') == 'UDP'])
            }
        }
        return stats

    def get_system_stats(self):
        # Get enhanced overall system statistics with normalized CPU percentages
        # Returns dictionary with detailed CPU, memory, disk info

        try:
            # Get CPU times
            cpu_times = psutil.cpu_times()
            
            # Calculate total time across all cores for normalization
            total_user = cpu_times.user
            total_system = cpu_times.system
            total_idle = cpu_times.idle
            total_time = total_user + total_system + total_idle
            
            # Calculate percentages of total
            if total_time > 0:
                user_percent = round((total_user / total_time) * 100, 1)
                system_percent = round((total_system / total_time) * 100, 1)
                idle_percent = round((total_idle / total_time) * 100, 1)
            else:
                user_percent = 0
                system_percent = 0
                idle_percent = 100
            
            # Get current CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_percent_per_core = psutil.cpu_percent(interval=1, percpu=True)
            cpu_count_physical = psutil.cpu_count(logical=False)
            cpu_count_logical = psutil.cpu_count(logical=True)
            cpu_freq = psutil.cpu_freq()
            
            # CPU load average (Windows uses different method)
            try:
                cpu_load = psutil.getloadavg()
                load_1min = cpu_load[0]
                load_5min = cpu_load[1]
                load_15min = cpu_load[2]
            except AttributeError:
                load_1min = cpu_percent
                load_5min = cpu_percent
                load_15min = cpu_percent
            
            # ========== MEMORY STATS ==========
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # ========== DISK STATS ==========
            disk_partitions = []
            total_disk_gb = 0
            used_disk_gb = 0
            free_disk_gb = 0
            
            try:
                for partition in psutil.disk_partitions():
                    try:
                        # Skip CD-ROM and floppy drives
                        if 'cdrom' in partition.opts.lower():
                            continue
                        if not partition.mountpoint:
                            continue
                        
                        usage = psutil.disk_usage(partition.mountpoint)
                        if usage.total > 0:
                            partition_info = {
                                'device': partition.device,
                                'mountpoint': partition.mountpoint,
                                'fstype': partition.fstype,
                                'total_gb': round(usage.total / (1024**3), 2),
                                'used_gb': round(usage.used / (1024**3), 2),
                                'free_gb': round(usage.free / (1024**3), 2),
                                'percent': usage.percent
                            }
                            disk_partitions.append(partition_info)
                            total_disk_gb += partition_info['total_gb']
                            used_disk_gb += partition_info['used_gb']
                            free_disk_gb += partition_info['free_gb']
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
            except Exception as e:
                logging.warning(f"Error reading disk partitions: {e}")
                # Fallback to C drive
                try:
                    usage = psutil.disk_usage('C:\\')
                    partition_info = {
                        'device': 'C:\\',
                        'mountpoint': 'C:\\',
                        'fstype': 'NTFS',
                        'total_gb': round(usage.total / (1024**3), 2),
                        'used_gb': round(usage.used / (1024**3), 2),
                        'free_gb': round(usage.free / (1024**3), 2),
                        'percent': usage.percent
                    }
                    disk_partitions = [partition_info]
                    total_disk_gb = partition_info['total_gb']
                    used_disk_gb = partition_info['used_gb']
                    free_disk_gb = partition_info['free_gb']
                except Exception as disk_error:
                    logging.error(f"Error getting C drive: {disk_error}")
                    disk_partitions = []
                    total_disk_gb = 0
                    used_disk_gb = 0
                    free_disk_gb = 0
            
            disk_overall = {
                'total_gb': round(total_disk_gb, 2),
                'used_gb': round(used_disk_gb, 2),
                'free_gb': round(free_disk_gb, 2),
                'percent': round((used_disk_gb / total_disk_gb * 100), 2) if total_disk_gb > 0 else 0
            }
            
            # ========== NETWORK STATS ==========
            net_io = psutil.net_io_counters()
            
            # ========== BATTERY INFO ==========
            battery = None
            if hasattr(psutil, 'sensors_battery'):
                bat = psutil.sensors_battery()
                if bat:
                    battery = {
                        'percent': bat.percent,
                        'power_plugged': bat.power_plugged,
                        'seconds_left': bat.secsleft if bat.secsleft != -1 else None
                    }
            
            # ========== BOOT TIME & UPTIME ==========
            boot_time_ts = psutil.boot_time()
            try:
                boot_time_str = datetime.fromtimestamp(boot_time_ts).strftime('%Y-%m-%d %H:%M:%S')
            except:
                boot_time_str = str(boot_time_ts)
            
            uptime_seconds = time.time() - boot_time_ts
            uptime_days = int(uptime_seconds // 86400)
            uptime_hours = int((uptime_seconds % 86400) // 3600)
            uptime_minutes = int((uptime_seconds % 3600) // 60)
            
            # ========== BUILD STATS DICTIONARY ==========
            stats = {
                'timestamp': datetime.now().isoformat(),
                'cpu': {
                    'percent': cpu_percent,
                    'percent_per_core': [round(p, 1) for p in cpu_percent_per_core],
                    'count_physical': cpu_count_physical,
                    'count_logical': cpu_count_logical,
                    'frequency_mhz': round(cpu_freq.current, 0) if cpu_freq else None,
                    'load_1min': round(load_1min, 1),
                    'load_5min': round(load_5min, 1),
                    'load_15min': round(load_15min, 1),
                    'times': {
                        'user': user_percent,
                        'system': system_percent,
                        'idle': idle_percent
                    }
                },
                'memory': {
                    'total_gb': round(memory.total / (1024**3), 2),
                    'available_gb': round(memory.available / (1024**3), 2),
                    'used_gb': round(memory.used / (1024**3), 2),
                    'free_gb': round(memory.free / (1024**3), 2),
                    'percent': memory.percent,
                    'swap': {
                        'total_gb': round(swap.total / (1024**3), 2),
                        'used_gb': round(swap.used / (1024**3), 2),
                        'free_gb': round(swap.free / (1024**3), 2),
                        'percent': swap.percent if swap.total > 0 else 0
                    }
                },
                'disk': {
                    'overall': disk_overall,
                    'partitions': disk_partitions
                },
                'network': {
                    'bytes_sent_mb': round(net_io.bytes_sent / (1024**2), 2),
                    'bytes_recv_mb': round(net_io.bytes_recv / (1024**2), 2),
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv,
                    'errin': net_io.errin,
                    'errout': net_io.errout
                },
                'system': {
                    'boot_time': boot_time_str,
                    'uptime_days': uptime_days,
                    'uptime_hours': uptime_hours,
                    'uptime_minutes': uptime_minutes
                },
                'battery': battery
            }
            
            return stats
            
        except Exception as e:
            logging.error(f"Error getting system stats: {str(e)}")
            import traceback
            traceback.print_exc()
            return {}
        
    def is_defender_disabled(self):
        """Returns True if Windows Defender real-time protection is disabled."""
        import subprocess
        import json
        try:
            cmd = ["powershell.exe", "-Command", "Get-MpComputerStatus | Select-Object -Property RealTimeProtectionEnabled | ConvertTo-Json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, list) and len(data) > 0:
                    enabled = data[0].get('RealTimeProtectionEnabled')
                else:
                    enabled = data.get('RealTimeProtectionEnabled')
                if enabled is False:
                    return True
        except Exception as e:
            print(f"[Defender] PowerShell query failed: {e}")
        # Fallback: check service status
        try:
            import win32serviceutil
            import win32service
            service_status = win32serviceutil.QueryServiceStatus("WinDefend")
            if service_status[1] != win32service.SERVICE_RUNNING:
                return True
        except:
            pass
        return False

    #######################################################################################################
    
    def get_process_summary(self):
        """Get process summary with top consumers"""
        processes = self.get_processes()
        if not processes:
            return {}
        
        top_cpu = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:5]
        top_memory = sorted(processes, key=lambda x: x['memory_percent'], reverse=True)[:5]
        
        users = {}
        for proc in processes:
            user = proc.get('username', 'Unknown')
            users[user] = users.get(user, 0) + 1
        
        return {
            'total_processes': len(processes),
            'top_cpu': [{'name': p['name'], 'cpu': p['cpu_percent']} for p in top_cpu],
            'top_memory': [{'name': p['name'], 'memory': p['memory_percent']} for p in top_memory],
            'users': users
        }
    
    def find_process_by_name(self, name):
        """Find processes by name"""
        processes = self.get_processes()
        return [p for p in processes if name.lower() in p['name'].lower()]