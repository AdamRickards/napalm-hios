# POLO — Persistent Operations through Local Onboarding

MARCO shouts. POLO answers. POLO is the dnsmasq registry — the memory of what SHOULD be on the network. MARCO is the eyes — what IS on the network. The diff between them is your network health status at any moment.

## Three States

```
MARCO scan:
  ✓ 00:80:63:aa:aa:aa — 10.0.1.1 — MATCHED.  In POLO, on wire. Healthy.
  ✗ 00:80:63:cc:cc:cc — 10.0.1.3 — MISSING.  In POLO, not on wire. Dead switch.
  ? 00:80:63:dd:dd:dd — 169.254.x.x — UNKNOWN. On wire, not in POLO. New/unconfigured.
```

Unknown is either: the replacement for the missing one (POLO re-registers new MAC against old IP/config) or a brand new addition (MOHAWC commissions it, POLO registers it).

## Self-Healing Loop

Switch dies → MARCO sees missing, POLO still has config. Tech plugs in replacement → MARCO sees unknown, POLO feeds it config. Loop closed. No remote intervention needed.

- [ ] POLO dnsmasq registry — MAC→IP→config mapping, TFTP server for config files
- [ ] MARCO integration — scan + compare against POLO registry, detect missing/unknown/matched
- [ ] Timer escalation — three levels, each more aggressive:
  1. **Happy path**: DHCP assigns IP from POLO, TFTP boot pulls config automatically. Done
  2. **Sad path**: MOHAWC logs in (default or known creds), CLI `copy config tftp://polo/switch3.cfg`. Switch pulls own config from POLO's TFTP. No reboot, no factory reset, just "here's your config, load it." Seconds, not minutes. Switch doesn't drop out of ring during reboot cycle
  3. **Sadder path**: TFTP pull fails → MOHAWC factory resets + reboot (nuclear option, 2-3 minutes on HiOS)
- [ ] 99% of the time it never gets past step 1
- [ ] MARCO/POLO continuously validate each other. MARCO is the eyes, POLO is the memory

## Driver Dependencies

- `get_tftp()` / `set_tftp()` in napalm-hios — TFTP config pull + auto-backup on save
- MOHAWC `--tftp-pull` subcommand wraps `set_tftp(server, filename, action='pull')`
