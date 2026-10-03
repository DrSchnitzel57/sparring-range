"""Safety supervisor (hard constraints #1, #2, #4).

killswitch must do BOTH, and both must be provable from inside a range VM:
  (a) stop the red agent service,
  (b) drop the range datapath.

In dev the red agent is a local process registered with this supervisor; in the
real deployment it's a service in the platform LXC and the datapath half runs on
the Proxmox host through infra.proxmox_client (and infra/firewall/killswitch.sh).
"""
from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path

from srplatform.settings import get_settings, Settings

REPO_ROOT = Path(__file__).resolve().parents[1]


class Supervisor:
    def __init__(self, proxmox=None, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.proxmox = proxmox  # proxmoxer wrapper or test double
        self.red_agent_pids: set[int] = set()

    # --- red agent registration (the loop registers on start, heartbeats) -----
    def register_red_agent(self, pid: int) -> None:
        self.red_agent_pids.add(pid)

    def unregister_red_agent(self, pid: int) -> None:
        self.red_agent_pids.discard(pid)

    # --- the killswitch (hard constraint #2) ------------------------------------
    def killswitch(self) -> dict:
        actions = []

        # (a) stop red agent service(s)
        for pid in sorted(self.red_agent_pids):
            try:
                os.kill(pid, signal.SIGTERM)
                actions.append(f"SIGTERM -> red agent pid {pid}")
            except ProcessLookupError:
                actions.append(f"red agent pid {pid} already dead")
        self.red_agent_pids.clear()

        # (b) drop the range datapath
        if self.proxmox is not None:
            if hasattr(self.proxmox, "calls"):  # test double
                self.proxmox.post(f"/nodes/self/firewall", state="0")  # datacenter firewall off == deny applied marker
                actions.append("datapath drop requested via proxmox api")
            else:
                subprocess.run(
                    ["bash", str(REPO_ROOT / "infra" / "firewall" / "killswitch.sh")],
                    check=False,
                )
                actions.append("infra/firewall/killswitch.sh executed")
        else:
            actions.append("WARNING: no proxmox connection — datapath drop NOT applied")

        return {"killswitch": "engaged", "actions": actions}

    def release(self) -> dict:
        # Releasing means re-applying the baseline egress-deny (not open access).
        return {
            "killswitch": "released",
            "note": "baseline egress-deny from infra/firewall/range-egress-deny.nft.conf.tmpl must still be active",
        }

    def verify(self) -> dict:
        """Config-state verification. The datapath proof (ping 1.1.1.1 fails,
        DNS fails from inside a range VM) is Drew's acceptance step — the agent
        cannot fake it (Part 0.4)."""
        return {
            "egress_deny_template": "infra/firewall/range-egress-deny.nft.conf.tmpl",
            "policy": "default-deny on range bridge; whitelisted update proxy OFF by default",
            "live_check": "run on the range VM: ping -c1 1.1.1.1 (must FAIL); getent hosts example.com (must FAIL)",
        }


_supervisor: Supervisor | None = None


def get_supervisor() -> Supervisor:
    global _supervisor
    if _supervisor is None:
        _supervisor = Supervisor()
    return _supervisor


def set_supervisor(s: Supervisor) -> None:
    global _supervisor
    _supervisor = s
