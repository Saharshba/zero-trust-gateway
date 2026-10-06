"""Trust scoring.

Zero trust does not mean "no trust"; it means trust is *computed per request*
from current signals instead of inherited from network location. The score is
a 0-100 number that policies can require a minimum of.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

# Identity alone is worth something, but not much: the whole point is that a
# valid password is not sufficient evidence.
BASE_AUTHENTICATED = 25
MFA_BONUS = 25
REGISTERED_DEVICE_BONUS = 20
POSTURE_SIGNAL_BONUS = 5          # per healthy posture signal, four of them
KNOWN_NETWORK_BONUS = 10
QUARANTINED_PENALTY = 60
UNKNOWN_DEVICE_PENALTY = 10


@dataclass(frozen=True)
class DevicePosture:
    device_id: str | None = None
    registered: bool = False
    quarantined: bool = False
    disk_encrypted: bool = False
    screen_lock: bool = False
    os_up_to_date: bool = False
    endpoint_protection: bool = False

    @property
    def healthy_signals(self) -> int:
        return sum(
            (self.disk_encrypted, self.screen_lock, self.os_up_to_date, self.endpoint_protection)
        )


def in_any_network(ip: str, cidrs: list[str]) -> bool:
    """True when `ip` falls inside any of `cidrs`. Bad input is not a match."""
    if not ip or not cidrs:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if address in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def trust_score(
    *,
    authenticated: bool,
    mfa_satisfied: bool = False,
    posture: DevicePosture | None = None,
    source_ip: str = "",
    known_networks: list[str] | None = None,
) -> int:
    """Return a 0-100 trust score for this request.

    Not authenticated is always 0: there is no partial credit for a device
    alone, because a device can be stolen.
    """
    if not authenticated:
        return 0

    score = BASE_AUTHENTICATED
    if mfa_satisfied:
        score += MFA_BONUS

    posture = posture or DevicePosture()
    if posture.quarantined:
        score -= QUARANTINED_PENALTY
    elif posture.registered:
        score += REGISTERED_DEVICE_BONUS + posture.healthy_signals * POSTURE_SIGNAL_BONUS
    else:
        score -= UNKNOWN_DEVICE_PENALTY

    if in_any_network(source_ip, known_networks or []):
        score += KNOWN_NETWORK_BONUS

    return max(0, min(100, score))
