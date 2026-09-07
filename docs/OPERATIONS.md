# Operations Runbook

## Daily
- Check feed freshness.
- Check connector health.
- Check PostgreSQL disk/WAL/replication.
- Check exporter snapshot age.
- Check Blocky DNS error rate and reload status.

## Feed incident
1. Disable affected source.
2. Preserve last-known-good snapshot.
3. Inspect feed import audit.
4. Compare raw hash/size against previous versions.
5. Re-run parser fixture against downloaded copy.
6. Re-enable only after validation.

## Rollback
- Set exporter current snapshot to previous version atomically.
- Verify manifest/checksum.
- Force Blocky refresh if needed.
- Record incident and reason.

## Security incident
- Revoke compromised feed credential.
- Disable source.
- Freeze automatic policy escalation.
- Review newly imported indicators.
- Rebuild snapshots from trusted sources.
