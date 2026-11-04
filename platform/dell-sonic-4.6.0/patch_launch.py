#!/usr/bin/env python3
"""sfab patch for vrnetlab dell/dell_sonic/docker/launch.py (SONiC 4.6.0 under containerlab).

usage: python3 patch_launch.py <path to launch.py>

It turns launch.py.upstream-plus-numnics, vrnetlab's launcher at the commit spec/versions.yaml pins
(images.dell_sonic.vrnetlab) plus the NUM_NICS line, into launch.py.patched (README.md, Building
it). The methods it writes keep some of vrnetlab's own lines, under vrnetlab's MIT licence
(LICENSE.vrnetlab).
"""
import pathlib
import sys

p = pathlib.Path(sys.argv[1])
s = p.read_text()

NEW_BOOTSTRAP = '''    def bootstrap_config(self):
        """sfab bootstrap for SONiC 4.6.0 under containerlab.

        1. Set the containerlab password.
        2. Clear the first-boot deadlock: the ntpsec-ntpdate if-up hook starts ntpsec, which waits for
           networking, which waits for ifup, which waits for the hook. Until it clears, interfaces-config
           never finishes, hostcfgd never starts, eth0 stays down and sshd listens on IPv6 only.
        3. Wait until systemd reports the system running (or degraded).
        4. Configure the management interface (slirp: 10.0.0.15/24, gateway 10.0.0.2) and the hostname
           through sonic-cli (KLISH), then write memory.
        """
        self.logger.info("applying bootstrap configuration")
        self.wait_write("sudo -i", "$")
        self.wait_write("passwd -q %s" % (self.username), "#")
        self.wait_write(self.password, "New password:")
        self.wait_write(self.password, "password:")
        self.wait_write("sleep 1", "#")
        clear = ("chmod -x /etc/network/if-up.d/ntpsec-ntpdate; "
                 "pkill -f /etc/network/if-up.d/ntpsec-ntpdate; "
                 "pkill -f 'invoke-rc.d --quiet ntpsec start'; "
                 "systemctl mask --now fstrim.timer >/dev/null 2>&1; systemctl stop fstrim.service >/dev/null 2>&1; "
                 "pkill -f 'smartctl -a' ; echo SFAB_HOOK_CLEARED")
        self.wait_write(clear, "#")
        gro_unit = "W1VuaXRdCkRlc2NyaXB0aW9uPXNmYWI6IEdSTyBhbmQgTFJPIG9mZiBvbiB0aGUgZGF0YSBOSUNzICh2cyBTQUkgY2Fubm90IHRha2UgbWVyZ2VkIGZyYW1lcyBvdmVyIDE2Mzg0IGJ5dGVzKQpBZnRlcj1uZXR3b3JrLnRhcmdldAoKW1NlcnZpY2VdClR5cGU9b25lc2hvdApFeGVjU3RhcnQ9L2Jpbi9zaCAtYyAnZm9yIGkgaW4gJCQobHMgL3N5cy9jbGFzcy9uZXQgfCBncmVwIC1FICJeZXRoWzEtOV1bMC05XSokJCIpOyBkbyAvdXNyL3NiaW4vZXRodG9vbCAtSyAkJGkgZ3JvIG9mZiByeC1ncm8taHcgb2ZmIGxybyBvZmY7IGRvbmU7IHRydWUnClJlbWFpbkFmdGVyRXhpdD15ZXMKCltJbnN0YWxsXQpXYW50ZWRCeT1tdWx0aS11c2VyLnRhcmdldAo="
        self.wait_write("echo %s | base64 -d > /etc/systemd/system/sfab-gro-off.service && systemctl daemon-reload && systemctl enable --now sfab-gro-off.service >/dev/null 2>&1; echo SFAB_GRO_OFF" % gro_unit, "#")
        # ZTP otherwise keeps discovering, rewrites port-group speeds and floods the console.
        # It reloads services; the next '#' prompt only appears once it has finished.
        self.wait_write("ztp disable -y", "#")
        self.wait_write("echo SFAB_ZTP_DONE", "#")
        ready = False
        attempt = 0
        for attempt in range(90):
            # never wait on a prompt inside this loop: expect() may consume it, and a later wait would block
            self.wait_write('echo "SFAB_STATE=$(systemctl is-system-running)"', None)
            ridx, match, res = self.tn.expect(
                [rb"SFAB_STATE=(running|degraded)", rb"SFAB_STATE=(starting|initializing|maintenance|stopping|offline|unknown)"], 30)
            if match and ridx == 0:
                ready = True
                break
            time.sleep(10)
        self.logger.info("system ready: %s after %d checks" % (ready, attempt + 1))
        self.wait_write("", None)
        self.tn.read_until(b"#", 30)
        self.wait_write("exit", None)
        self.wait_write("sonic-cli", "$")
        self.wait_write("terminal length 0", "#")
        self.wait_write("configure terminal", "#")
        self.wait_write("interface Management 0", "(config)#")
        self.wait_write("ip address %s gwaddr %s" % (self.mgmt_address_ipv4, self.mgmt_gw_ipv4), "(config-if-Management0)#")
        self.wait_write("no shutdown", "(config-if-Management0)#")
        self.wait_write("exit", "(config-if-Management0)#")
        self.wait_write("hostname %s" % self.hostname, "(config)#")
        self.wait_write("end", "(config)#")
        self.wait_write("write memory", "#")
        self.wait_write("exit", "#")
        self.wait_write("logout", "$")
        self.logger.info("completed bootstrap configuration")

'''

NEW_STARTUP = '''    def startup_config(self):
        """Apply a startup configuration if one is mounted.

        /config/startup-config.cfg: KLISH lines, typed into sonic-cli on the serial console, then write memory.
        /config/config_db.json: the upstream path (backup.sh restore).
        """
        klish = "/config/startup-config.cfg"
        if os.path.exists(klish):
            self.logger.info("typing KLISH startup config %s" % klish)
            self.wait_write("\\r", None)
            self.wait_write(self.username, "login:")
            self.wait_write(self.password, "Password:")
            self.wait_write("sonic-cli", "$")
            self.wait_write("terminal length 0", "#")
            with open(klish) as f:
                for line in f:
                    line = line.rstrip("\\n")
                    if not line.strip() or line.lstrip().startswith("!"):
                        continue
                    self.wait_write(line, None)
                    time.sleep(0.3)
            self.wait_write("end", None)
            self.wait_write("write memory", "#")
            self.wait_write("exit", "#")
            self.wait_write("logout", "$")
            self.logger.info("KLISH startup config applied")
            return
        if not os.path.exists(CONFIG_FILE):
            self.logger.trace(f"Startup config file {CONFIG_FILE} is not provided, nothing to do")
            return
        self.logger.trace(f"Startup config file {CONFIG_FILE} found, copying it to the VM")
        subprocess.run(f"/backup.sh -u {self.username} -p {self.password} restore", check=True, shell=True)


'''

# NUM_NICS: the data NIC count per node (the upstream launcher fixes 10; a rail leaf needs 12)
if "        self.num_nics = 10\n" in s:
    s = s.replace("        self.num_nics = 10\n", "        self.num_nics = int(os.getenv(\"NUM_NICS\", \"10\"))\n")

a = s.index("    def bootstrap_config(self):")
b = s.index("    def startup_config(self):")
s = s[:a] + NEW_BOOTSTRAP + s[b:]
a = s.index("    def startup_config(self):")
b = s.index("class Dell_SONiC(vrnetlab.VR):")
s = s[:a] + NEW_STARTUP + s[b:]
if "\nimport time\n" not in s:
    s = s.replace("import sys\n", "import sys\nimport time\n", 1)
s = s.replace("        if self.spins > 300:", "        if self.spins > 3000:")
# container side: no IPv6 on the vrnetlab container's own data veths (they otherwise answer as hosts on the switch's VLANs).
# default covers veths containerlab attaches after start; existing eth1..N are set directly; eth0 (management) is left alone.
ipv6_off = (
    "    for _f in ['/proc/sys/net/ipv6/conf/default/disable_ipv6'] + sorted(\n"
    "            '/proc/sys/net/ipv6/conf/%s/disable_ipv6' % _n for _n in os.listdir('/proc/sys/net/ipv6/conf')\n"
    "            if re.match(r'^eth[1-9][0-9]*$', _n)):\n"
    "        try:\n"
    "            open(_f, 'w').write('1')\n"
    "        except OSError:\n"
    "            pass\n"
)
anchor = "    vr = Dell_SONiC(\n"
assert s.count(anchor) == 1
s = s.replace(anchor, ipv6_off + anchor)
p.write_text(s)
print("launcher patched:", p)
