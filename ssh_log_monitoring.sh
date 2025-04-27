#!/bin/bash

# Script pour surveiller et bloquer les attaques par force brute SSH

# Variables de configuration
LOG_FILE="/var/log/auth.log"
HOSTS_DENY="/etc/hosts.deny"
THRESHOLD=5
REPORT_FILE="/var/log/ssh_blocked_ips.log"
EMAIL="admin@votredomaine.com"

# Vérifier si le script est exécuté avec root
if [ "$EUID" -ne 0 ]; then
    echo "Ce script doit être exécuté en tant que root."
    exit 1
fi

# Vérifier si le fichier de log existe
if [ ! -f "$LOG_FILE" ]; then
    echo "Le fichier de log $LOG_FILE n'existe pas."
    exit 1
fi

# Extraire les IPs avec des tentatives échouées
FAILED_IPS=$(grep "Failed password" "$LOG_FILE" | \
             awk '{print $11}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
             sort | uniq -c | \
             awk -v threshold="$THRESHOLD" '$1 > threshold {print $2}')

# Vérifier si des IPs suspectes ont été trouvées
if [ -z "$FAILED_IPS" ]; then
    echo "Aucune IP suspecte détectée."
    exit 0
fi

# Traiter chaque IP suspecte
for IP in $FAILED_IPS; do
    if grep -q "$IP" "$HOSTS_DENY"; then
        echo "L'IP $IP est déjà bloquée."
    else
        echo "sshd: $IP" >> "$HOSTS_DENY"
        echo "IP $IP bloquée à $(date)" | tee -a "$REPORT_FILE"
        # Notification par e-mail (optionnel)
        echo "Alerte : L'IP $IP a été bloquée pour tentative de force brute SSH." | \
        mail -s "Alerte Brute Force SSH" "$EMAIL" 2>/dev/null
    fi
done

# Résumé
echo "Analyse terminée. Consultez $REPORT_FILE pour le rapport."

exit 0
