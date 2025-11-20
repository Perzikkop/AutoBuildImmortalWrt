#!/bin/sh
# 99-custom.sh 是 ImmortalWRT 固件首次启动时运行的脚本，位于 /etc/uci-defaults/99-custom.sh

LOGFILE="/tmp/uci-defaults-log.txt"
echo "Starting 99-custom.sh at $(date)" >> $LOGFILE

# 设置默认防火墙规则，方便虚拟机首次访问 WebUI
LAN_ZONE=$(uci show firewall | grep "=zone" | grep "'lan'" | cut -d. -f2 | head -n1)
if [ -n "$LAN_ZONE" ]; then
    uci set firewall.$LAN_ZONE.input='ACCEPT'
    uci commit firewall
fi

# 网络配置部分
NETWORK_CONFIG_MARKER="/opt/.network_configured"

if [ -f "$NETWORK_CONFIG_MARKER" ]; then
    echo "Network configuration already applied. Skipping network configuration." >> $LOGFILE
else
    echo "No network configuration marker found. Proceeding with network configuration." >> $LOGFILE

    # 1. 获取所有物理接口列表
    ifnames=""
    for iface in /sys/class/net/*; do
        iface_name=$(basename "$iface")
        if [ -e "$iface/device" ] && echo "$iface_name" | grep -Eq '^(eth|en|wan|lan)[0-9]*$'; then
            ifnames="$ifnames $iface_name"
        fi
    done
    ifnames=$(echo "$ifnames" | awk '{$1=$1};1')

    count=$(echo "$ifnames" | wc -w)
    echo "Detected physical interfaces: $ifnames" >>$LOGFILE
    echo "Interface count: $count" >>$LOGFILE

    # 2. 根据板子型号映射 WAN 和 LAN 接口
    board_name=$(cat /tmp/sysinfo/board_name 2>/dev/null || echo "unknown")
    echo "Board detected: $board_name" >>$LOGFILE

    wan_ifname=""
    lan_ifnames=""
    case "$board_name" in
        "radxa,e20c"|"friendlyarm,nanopi-r5c")
            wan_ifname="eth1"
            lan_ifnames="eth0"
            echo "Using $board_name mapping: WAN=$wan_ifname LAN=$lan_ifnames" >>"$LOGFILE"
            ;;
        *)
            wan_ifname=$(echo "$ifnames" | awk '{print $1}')
            lan_ifnames=$(echo "$ifnames" | cut -d ' ' -f2-)
            echo "Using default mapping: WAN=$wan_ifname LAN=$lan_ifnames" >>"$LOGFILE"
            ;;
    esac

    # 3. 配置网络
    if [ "$count" -eq 1 ]; then
        # 单网口设备，DHCP 模式
        uci set network.lan.proto='dhcp'
        uci -q delete network.lan.ipaddr
        uci -q delete network.lan.netmask
        uci -q delete network.lan.gateway
        uci -q delete network.lan.dns
        uci commit network
    elif [ "$count" -gt 1 ]; then
        # 多网口设备配置
        # 配置 WAN
        uci set network.wan.proto='dhcp'
        uci set network.wan.device="$wan_ifname"

        # 配置 WAN6
        uci set network.wan6.proto='dhcpv6'
        uci set network.wan6.device="$wan_ifname"

        # 配置 br-lan 设备端口
        section=$(uci show network | awk -F '[.=]' '/\.@device\[[0-9]+\]\.name=.br-lan.$/ {print $2; exit}')
        if [ -z "$section" ]; then
            echo "error: cannot find device 'br-lan'." >>$LOGFILE
        else
            uci -q delete "network.$section.ports"
            for port in $lan_ifnames; do
                uci add_list "network.$section.ports"="$port"
            done
            echo "Updated br-lan ports: $lan_ifnames" >>$LOGFILE
        fi

        # LAN 静态 IP
        uci set network.lan.proto='static'
        uci set network.lan.netmask='255.255.255.0'

        IP_VALUE_FILE="/etc/config/custom_router_ip.txt"
        if [ -f "$IP_VALUE_FILE" ]; then
            CUSTOM_IP=$(cat "$IP_VALUE_FILE")
            uci set network.lan.ipaddr=$CUSTOM_IP
            echo "custom router ip is $CUSTOM_IP" >> $LOGFILE
        else
            uci set network.lan.ipaddr='192.168.20.1'
            echo "default router ip is 192.168.20.1" >> $LOGFILE
        fi

        # PPPoE 设置
        PPPOE_FILE="/etc/config/pppoe_settings"
        if [ -f "$PPPOE_FILE" ]; then
            . "$PPPOE_FILE"
            echo "enable_pppoe value: $enable_pppoe" >>$LOGFILE
            if [ "$enable_pppoe" = "yes" ]; then
                echo "PPPoE enabled, configuring..." >>$LOGFILE
                uci set network.wan.proto='pppoe'
                uci set network.wan.username="$pppoe_account"
                uci set network.wan.password="$pppoe_password"
                uci set network.wan.peerdns='1'
                uci set network.wan.auto='1'
                uci set network.wan6.proto='none'
                echo "PPPoE config done." >>$LOGFILE
            else
                echo "PPPoE not enabled." >>$LOGFILE
            fi
        else
            echo "PPPoE settings file not found. Skipping PPPoE configuration." >> $LOGFILE
        fi

        uci commit network
    fi
fi

# 若安装了 dockerd 则配置 Docker 防火墙规则
if command -v dockerd >/dev/null 2>&1; then
    echo "检测到 Docker，正在配置防火墙规则..." >> $LOGFILE

    uci -q delete firewall.docker
    # 删除所有和 docker 相关的 forwarding
    for idx in $(uci show firewall | grep "=forwarding" | cut -d[ -f2 | cut -d] -f1 | sort -rn); do
        src=$(uci get firewall.@forwarding[$idx].src 2>/dev/null)
        dest=$(uci get firewall.@forwarding[$idx].dest 2>/dev/null)
        if [ "$src" = "docker" ] || [ "$dest" = "docker" ]; then
            uci delete firewall.@forwarding[$idx]
        fi
    done

    uci set firewall.docker=zone
    uci set firewall.docker.name='docker'
    uci set firewall.docker.input='ACCEPT'
    uci set firewall.docker.output='ACCEPT'
    uci set firewall.docker.forward='ACCEPT'
    uci add_list firewall.docker.subnet='172.16.0.0/12'

    uci add firewall forwarding
    uci set firewall.@forwarding[-1].src='docker'
    uci set firewall.@forwarding[-1].dest='lan'

    uci add firewall forwarding
    uci set firewall.@forwarding[-1].src='docker'
    uci set firewall.@forwarding[-1].dest='wan'

    uci add firewall forwarding
    uci set firewall.@forwarding[-1].src='lan'
    uci set firewall.@forwarding[-1].dest='docker'

    uci commit firewall
else
    echo "未检测到 Docker，跳过防火墙配置。" >> $LOGFILE
fi

# 设置所有网口可访问网页终端
uci -q delete ttyd.@ttyd[0].interface

# 允许所有网口连接 SSH
uci set dropbear.@dropbear[0].Interface=''
uci commit dropbear

# 修改编译者信息
FILE_PATH="/etc/openwrt_release"
NEW_DESCRIPTION="Compiled by Ananaskop"
sed -i "s/DISTRIB_DESCRIPTION='[^']*'/DISTRIB_DESCRIPTION='$NEW_DESCRIPTION'/" "$FILE_PATH"

# 去除 luci-app-advancedplus 的 zsh 调用
if opkg status luci-app-advancedplus >/dev/null 2>&1; then
    sed -i '/\/usr\/bin\/zsh/d' /etc/profile
    sed -i '/\/bin\/zsh/d' /etc/init.d/advancedplus
    sed -i '/\/usr\/bin\/zsh/d' /etc/init.d/advancedplus
fi

# 修改默认 shell 为 bash
if grep -q "/bin/ash" /etc/passwd; then
    sed -i 's#/bin/ash#/bin/bash#g' /etc/passwd
fi

# 修改 SSH 登录欢迎信息（/etc/banner）
cat << EOF > /etc/banner
-------------------------------------
 Welcome to ImmortalWrt by Perzikkop!
-------------------------------------
EOF
chmod 644 /etc/banner

exit 0