#!/bin/sh
set -eu
mkdir -p /oracle /work /run /var/run
cat > /oracle/w.sh <<'EOF'
#!/bin/sh
printf '%s\n' 'PFSENSE-IPSEC-LOGIN-BANNER-WITNESS' > /oracle/PFSENSE-IPSEC-LOGIN-BANNER-WITNESS
EOF
chmod 755 /oracle/w.sh
rm -f /oracle/PFSENSE-IPSEC-LOGIN-BANNER-WITNESS
echo "oracle-writer /oracle/w.sh"
ls -l /usr/libexec/ipsec/charon /usr/lib/ipsec/charon /usr/sbin/ipsec 2>/dev/null || true
exec python3 -m http.server 18850 --bind 0.0.0.0
