# platform = multi_platform_all
# complexity = low
# reboot = false
# disruption = low
# strategy = disable

# CAUTION: This remediation script will remove openssh
#	   from the system, and may remove any packages
#	   that depend on openssh. Execute this
#	   remediation AFTER testing on a non-production
#	   system!

printf '%s\n' "Can't generate a remediation for zypper" >&2
exit 1