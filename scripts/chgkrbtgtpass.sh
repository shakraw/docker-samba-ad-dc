#!/bin/bash
#See: https://samba.tranquil.it/doc/en/samba_advanced_methods/samba_reset_krbtgt.html

set -x

while true
do
#TESTING BEGIN - get all dcs to replicate to
# sleep 10m
#  ALLDC=$(ldbsearch -H /var/lib/samba/private/sam.ldb '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' | grep dn: | sed 's/dn: /\n/g' | sed '/^[[:space:]]*$/d')
#  IFS=$'\n'
#  for dc in ${ALLDC}; do
#    if [ ! "$HOSTNAME" = "$dc" ]; then
#	  samba-tool drs replicate "$dc" "$HOSTNAME" "$LDAP_SUFFIX"
#      samba-tool drs replicate "$dc" "$HOSTNAME" "DC=ForestDnsZones$LDAP_SUFFIX"
#      samba-tool drs replicate "$dc" "$HOSTNAME" "CN=Configuration$LDAP_SUFFIX"
#      samba-tool drs replicate "$dc" "$HOSTNAME" "DC=DomainDnsZones$LDAP_SUFFIX"
#      samba-tool drs replicate "$dc" "$HOSTNAME" "CN=Schema,CN=Configuration$LDAP_SUFFIX"
#	fi
#  done
#  IFS=' '
#TESTING END
  echo "changing Kerberos Ticket Granting Ticket (TGT) password"
  if python3 /"${DIR_SCRIPTS}"/chgkrbtgtpass-v4-15-stable.py | tee /var/log/chgkrbtgtpass.log; then
    echo "SUCCESS: Changed KRBTGT password"
	# Change a second time
	python3 /"${DIR_SCRIPTS}"/chgkrbtgtpass-v4-15-stable.py
  else
    echo "ERROR: Failed chainging KRBTGT password" && exit 1
  fi

  date1="$(date +"%a, %d %b %Y %H:%M:%S %Z")"
  lastset="$(pdbedit -Lv krbtgt | grep "Password last set:")"
  date2="$(echo "$lastset" | cut -d ':' -f2):$(echo "$lastset" | cut -d ':' -f3):$(echo "$lastset" | cut -d ':' -f4)"
  #remove leading spaces
  date2=$(echo $date2 | sed 's/^ *//g')
  echo "Verifying that KRBTGT password has been updated"
  echo "Current date and time"
  echo "$date1"
  echo "$lastset"
  
  if [ "$date1" = "$date2" ]; then
    echo "Verify OK"
  else
    echo "Verify FAILED"
   ## exit 1
  fi
  #pdbedit -Lv krbtgt # grep password change date => compare to current date => replicate (samba-tool drs replicate <remote_dc> <pdc_dc> dc=mydomain,dc=lan)
sleep 40d
done
