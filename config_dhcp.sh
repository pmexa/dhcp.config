#!/bin/bash

if [ "$EUID" -ne 0 ];then
	echo "Tem  de estar em root"
	exit 1
fi
echo "A atualizar pacotes..."
dnf -y update
echo "A detetar interfaces de rede..."
nmcli device status

NAT_IF="ens160"
LAN_IF="ens224"
STATIC_IP="192.168.10.1"
NETMASK="255.255.255.0"
GATEWAY="192.168.10.1"
DNS="8.8.8.8"
DHCP_RANGE_START="192.168.10.20"
DHCP_RANGE_END="192.168.10.30"
LEASE_TIME="40200"
DNS1="8.8.8.8"
DNS2="1.1.1.1"


echo "A instalar serviço DHCP"
dnf install -y dnsmasq


echo "A configurar IP estático em $LAN_IF"
nmcli connection modify $LAN_IF ipv4.addresses $STATIC_IP/24
nmcli connection modify $LAN_IF ipv4.gateway $GATEWAY
nmcli connection modify $LAN_IF ipv4.dns $DNS
nmcli connection down $LAN_IF && nmcli connection up $LAN_IF
echo "IP estático configurado em ${LAN_IF}"

DHCP_CONF="/etc/dnsmasq.conf"
echo "A configurar o ficheiro ${DHCP_CONF}..."
cat > "$DHCP_CONF" <<config
interface=$LAN_IF
bind-interfaces

server=$DNS1
server=$DNS2

dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,$LEASE_TIME
dhcp-option=option:router,$GATEWAY
dhcp-option=option:ntp-server,$STATIC_IP
config

systemctl restart dnsmasq

echo "Ficheiro de configuração DHCP criado com sucesso"

echo "A ativar e iniciar o serviço DHCP..."
systemctl enable --now dnsmasq
echo "A abrir porta 67/UDP na firewall..."
firewall-cmd --add-service=dhcp
firewall-cmd --runtime-to-permanent

echo "A abrir porta 53/TCP na firewall..."
firewall-cmd --add-service=dns
firewall-cmd --runtime-to-permanent

systemctl status dnsmasq --no-pager

echo "A dar acesso à internet aos clientes..."
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
iptables -t nat -A POSTROUTING -o $NAT_IF -j MASQUERADE
firewall-cmd --permanent --add-masquerade
firewall-cmd --reload

echo "Configuração concluída com sucesso"
echo "Interface LAN:"
ip addr show $LAN_IF | grep "inet "
echo "O servidor DHCP está ativo e a distribuir IPs pela interface $LAN_IF"
