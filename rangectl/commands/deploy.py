"""Implementation functions behind `rangectl deploy|reset|teardown` (M1).
Pure API clients (front-door rule): the orchestrator inside the API does the
proxmoxer work; these just call it and print.
"""
import httpx

from srplatform.settings import get_settings


def deploy(scenario_id: str) -> str:
    r = httpx.post(f"{get_settings().api_base_url}/deploy/{scenario_id}", timeout=300)
    r.raise_for_status()
    lines = [f"  cloned {h['name']} (vmid {h['vmid']}, {h['ip']})" for h in r.json()["hosts"]]
    return "\n".join(lines)


def reset(scenario_id: str) -> str:
    r = httpx.post(f"{get_settings().api_base_url}/deploy/{scenario_id}/reset", timeout=300)
    r.raise_for_status()
    out = r.json()
    lines = [f"  destroyed {n}" for n in out.get("removed", [])]
    lines += [f"  re-cloned {h['name']} (vmid {h['vmid']}, {h['ip']})" for h in out["hosts"]]
    return "\n".join(lines)


def teardown(scenario_id: str) -> tuple[str, int]:
    r = httpx.post(f"{get_settings().api_base_url}/deploy/{scenario_id}/teardown", timeout=300)
    r.raise_for_status()
    out = r.json()
    lines = [f"  destroyed {n}" for n in out.get("removed", [])]
    if out["orphans"]:
        lines.append(f"  ORPHANS: {out['orphans']}")
        return "\n".join(lines), 1
    return "\n".join(lines), 0
