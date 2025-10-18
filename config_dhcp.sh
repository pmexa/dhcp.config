#!/bin/bash

is_valid_ip() {
    local ip=$1
    local stat=1
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        OIFS=$IFS; IFS='.'; ip=($ip); IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

is_valid_interface() {
    nmcli device show "$1" &>/dev/null
}

if [ "$EUID" -ne 0 ]; then
    echo "  Tem de estar em root para executar este script."
    exit 1
fi

dnf -y update

echo "**********************************"
echo "*   Script de Configuração DHCP  *"
echo "**********************************"
echo
echo "Interfaces de rede disponíveis:"
nmcli device status


while true; do
    read -p " Introduza a interface de saída (NAT): " NAT_IF
    if is_valid_interface "$NAT_IF"; then break
    else echo " Interface inválida. Tente novamente."; fi
done

while true; do
    read -p " Introduza a interface da rede interna (LAN): " LAN_IF
    if is_valid_interface "$LAN_IF"; then break
    else echo " Interface inválida. Tente novamente."; fi
done

while ! nmcli device show "$LAN_IF" &>/dev/null || [ "$LAN_IF" = "$NAT_IF" ]; do
    echo " Interface inválida ou igual à NAT."
    read -p " Introduza novamente a interface LAN: " LAN_IF
done

while ! nmcli device show "$NAT_IF" &>/dev/null || [ "$LAN_IF" = "$NAT_IF" ]; do
    echo " Interface inválida ou igual à LAN."
    read -p " Introduza novamente a interface NAT: " NAT_IF
done

echo " ----------Configurar IP Estático----------"
while true; do
    read -p " Introduza o IP estático da LAN (ex: 192.168.10.1): " STATIC_IP
    if is_valid_ip "$STATIC_IP"; then break
    else echo " IP inválido. Tente novamente."; fi
done

echo "----------Configurar Gateway----------"
while true; do
    read -p " Introduza o gateway (ex: 192.168.10.1): " GATEWAY
    if is_valid_ip "$GATEWAY"; then break
    else echo " Gateway inválido. Tente novamente."; fi
done

echo "----------Configurar DNS----------"
while true; do
    read -p " Introduza o DNS principal (ex: 8.8.8.8): " DNS1
    if is_valid_ip "$DNS1"; then break
    else echo " DNS inválido. Tente novamente."; fi
done

while true; do
    read -p " Introduza o DNS secundário (ex: 1.1.1.1): " DNS2
    if is_valid_ip "$DNS2"; then break
    else echo " DNS inválido. Tente novamente."; fi
done

echo "----------Configurar Intervalo DHCP ----------"
while true; do
    read -p " Início do intervalo DHCP (ex: 192.168.10.20): " DHCP_RANGE_START
    if is_valid_ip "$DHCP_RANGE_START"; then break
    else echo " IP inválido. Tente novamente."; fi
done

while true; do
    read -p " Fim do intervalo DHCP (ex: 192.168.10.30): " DHCP_RANGE_END
    if is_valid_ip "$DHCP_RANGE_END"; then break
    else echo " IP inválido. Tente novamente."; fi
done

echo "**********************************"
echo "*     A instalar serviço DHCP    *"
echo "**********************************"

dnf install -y dnsmasq

sleep 3

echo "A configurar IP estático em $LAN_IF"

nmcli connection modify $LAN_IF ipv4.addresses $STATIC_IP/24
nmcli connection modify $LAN_IF ipv4.gateway $GATEWAY
nmcli connection modify $LAN_IF ipv4.dns $DNS1","$DNS2
nmcli connection modify $LAN_IF ipv4.may-fail no
nmcli connection modify $LAN_IF ipv4.method manual
nmcli connection down $LAN_IF && nmcli connection up $LAN_IF


echo "IP estático configurado em $LAN_IF"
sleep 3
echo "A configurar o ficheiro dnsmasq.conf ..."
sleep 1
cat > /etc/dnsmasq.conf <<config
interface=$LAN_IF
bind-interfaces

server=$DNS1
server=$DNS2

dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END
dhcp-option=option:router,$GATEWAY
dhcp-option=option:ntp-server,$STATIC_IP
dhcp-option=option:dns-server,$STATIC_IP
config
echo "****************************************************"
echo "* Ficheiro de configuração DHCP criado com sucesso *"
echo "****************************************************"
echo
echo "****************************************************"
echo "*   A criar ficheiro backup da configuração DHCP   *"
echo "****************************************************"
DHCP_CONF="/etc/dnsmasq.conf"
if [ -f "$DHCP_CONF" ] && [ ! -f "${DHCP_CONF}.backup" ]; then
    cp "$DHCP_CONF" "${DHCP_CONF}.backup"
    echo " Backup criado: ${DHCP_CONF}.backup"
else
    echo " Backup já existe ou ficheiro não encontrado"
fi
sleep 2
echo "Ficheiro de configuração DHCP criado com sucesso"
sleep 3
echo "--------A ativar e iniciar o serviço DHCP----------"
systemctl enable --now dnsmasq
sleep 3
echo "--------A abrir porta 67/UDP na firewall-----------"
firewall-cmd --add-service=dhcp
sleep 2
echo "--------A abrir porta 53/TCP na firewall-----------"
sleep 2
firewall-cmd --add-service=dns
firewall-cmd --runtime-to-permanent

systemctl status dnsmasq --no-pager

echo "A dar acesso à internet aos clientes..."
sleep 3
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
iptables -t nat -A POSTROUTING -o $NAT_IF -j MASQUERADE
firewall-cmd --permanent --add-masquerade
firewall-cmd --reload

echo "-------A instalar e a configurar Security Enhanced Linux----------"
dnf install   policycoreutils selinux-policy selinux-policy-targeted policycoreutils-python-utils -y
sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
setenforce 1
semanage fcontext -a -t dnsmasq_etc_t "/etc/dnsmasq.conf"
semanage fcontext -a -t dnsmasq_etc_t "/etc/dnsmasq.d(/.*)?"
restorecon -Rv /etc/dnsmasq.conf /etc/dnsmasq.d

sleep 3

echo " -----------A instalar e a configurar Fail2Ban------------------- "
yum install epel-release -y
dnf install fail2ban -y
systemctl enable --now fail2ban

cat > /etc/fail2ban/jail.local <<config2
[DEFAULT]
bantime = 10m
findtime = 5m
maxretry = 5
backend = systemd
banaction = firewallcmd-ipset

[sshd]
enabled = true

[dnsmasq-dhcp]
enabled = true
port    = 67
filter  = dnsmasq-dhcp
logpath = /var/log/messages
maxretry = 10
config2

systemctl restart fail2ban
sleep 1
echo "Configuração concluída com sucesso"
echo "Interface LAN:"
ip addr show $LAN_IF | grep "inet "
sleep 1
echo "Servidor DHCP ativo na interface $LAN_IF"
