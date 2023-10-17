B='\033[0;34m'
R='\033[0;31m'
C='\033[0;36m'
N='\033[0m' # No Color

sudo apt-get update

# Checking the curl command exists or not
if ! command -v curl &>/dev/null; then
    echo -e "${R}curl is not be found, we are installing the curl command ${N}"
    sudo apt-get install curl -y
fi

PUBLIC_IP=$(curl https://ipinfo.io/ip)

echo -e "${B}Please enter PUBLIC PORT \nWe are suggesting anything between 1000-65535 ${N}"
read PUBLIC_PORT

echo -e "${B}Please enter WIREGUARD PORT \nWe are suggesting anything between 1000-65535 ${N}"
read WIREGUARD_PORT

echo -e "${B}Please enter your keyring password. \nNote: Please remember enter this password \nIt will requiresd when you query the sentinel dvpn node ${N}"
# add mnemonic to recover your account
# MNEMONIC="YOUR MNEMONIC"
read -s KEYRING_PASSWORD
# keyring password, your wish you can change this but
# when again access the sentinel-cli you have enter this password
# KEYRING_PASSWORD="sentineldvpn"

# please change this moniker name
# this will display on nodes list
# ex: sentinel-moniker-123
echo -e "${B}Please enter your moniker name. \nIt will display on the sentinel dvpn nodes list ${N}"
read MONIKER
# MONIKER="YOUR MONIKER NAME"

# add charges as per your wish
# ex : 500000uvpn
echo -e "${B}What is the price per gb, \nNote : 1DVPN = 1000000udvpn please use udvpn \nEx: 10000udvpn${N}"
read PRICE_PER_GB
# PRICE_PER_GB="YOUR PRICE"

# recover account into this username
# ex: supuser ...
# USERNAME="YOUR USERNAME"
echo -e "${B}What is account username${N}"
read USERNAME

echo -e "${B}Sentinel account is already exits , do you want import account : y/n ${N}"
read user_inp
if [ "$user_inp" == "y" ] || [ "$user_inp" == "Y" ]; then
    echo -e "${B}Please enter your mnemonic to restore your account${N}"
    read -s MNEMONIC
else
    echo -e "${C}It will create new account for you , do you have to save seed for restoring the account back${N}"
fi

sudo apt-get install openssl iptables-persistent curl -y

if ! command -v docker &>/dev/null; then
    echo -e "${R}docker is not installed, we are installing the docker${N}"
    curl https://get.docker.com | bash
fi

# pull the sentinel-dvpn node which is build using https://github.com/sentinel-official/dvpn-node/
docker pull ghcr.io/sentinel-official/dvpn-node:latest

echo "{                                                                    
    "ipv6": true,
    "fixed-cidr-v6": "2001:db8:1::/64"
}" >/etc/docker/daemon.json

rm /etc/iptables/rules.v6

rule="POSTROUTING -s 2001:db8:1::/64 ! -o docker0 -j MASQUERADE" &&
    sudo ip6tables -t nat -C ${rule} ||
    sudo ip6tables -t nat -A ${rule} &&
    sudo sh -c "ip6tables-save > /etc/iptables/rules.v6"

docker run --rm --volume ${HOME}/.sentinelnode:/root/.sentinelnode ghcr.io/sentinel-official/dvpn-node:latest bash -c "process config init"
docker run --rm --volume ${HOME}/.sentinelnode:/root/.sentinelnode ghcr.io/sentinel-official/dvpn-node:latest bash -c "process wireguard config init"

sed -i 's/^\(from\s*=\s*\).*$/\1\"'$(echo ${USERNAME})'\"/' ${HOME}/.sentinelnode/config.toml
sed -i 's/^\(moniker\s*=\s*\).*$/\1\"'$(echo ${MONIKER})'\"/' ${HOME}/.sentinelnode/config.toml
sed -i 's/^\(price\s*=\s*\).*$/\1\"'$(echo ${PRICE_PER_GB})'\"/' ${HOME}/.sentinelnode/config.toml
sed -i 's/^\(listen_on\s*=\s*\).*$/\1\"'$(echo 0.0.0.0:${PUBLIC_PORT})'\"/' ${HOME}/.sentinelnode/config.toml
sed -i 's/^\(remote_url\s*=\s*\).*$/\1\"https:\/\/'$(echo ${PUBLIC_IP}:${PUBLIC_PORT})'\"/' ${HOME}/.sentinelnode/config.toml

sed -i 's/^\(listen_port\s*=\s*\).*$/\1'$(echo ${WIREGUARD_PORT})'/' ${HOME}/.sentinelnode/wireguard.toml

openssl req -new \
    -newkey ec \
    -pkeyopt ec_paramgen_curve:prime256v1 \
    -x509 \
    -sha256 \
    -days 365 \
    -nodes \
    -out ${HOME}/.sentinelnode/tls.crt \
    -keyout ${HOME}/.sentinelnode/tls.key

echo $KEYRING_PASSWORD >${HOME}/.sentinelnode/keyring_password.txt

if [ -z ${MNEMONIC+x} ]; then
    echo -e "${B}Creating the new account${N}"
    echo $KEYRING_PASSWORD >>${HOME}/.sentinelnode/mnemonic.txt
    echo $KEYRING_PASSWORD >>${HOME}/.sentinelnode/mnemonic.txt
    docker run -it --rm --env USERNAME:${USERNAME} --name sentinel-dvpn-node-live --volume ${HOME}/.sentinelnode:/root/.sentinelnode ghcr.io/sentinel-official/dvpn-node:latest bash -c "process keys add ${USERNAME} < $HOME/.sentinelnode/mnemonic.txt"
    echo -e '\033[1mMake sure you have enough balance on above to run the dvpn node\033[0m'
    rm ${HOME}/.sentinelnode/mnemonic.txt
else
    echo -e "${B}Restoring account from your mnemonic${N}"
    echo $MNEMONIC >${HOME}/.sentinelnode/mnemonic.txt
    echo $KEYRING_PASSWORD >>${HOME}/.sentinelnode/mnemonic.txt
    echo $KEYRING_PASSWORD >>${HOME}/.sentinelnode/mnemonic.txt

    docker run -it --rm --env USERNAME:${USERNAME} --name ssentinel-dvpn-node-live --volume ${HOME}/.sentinelnode:/root/.sentinelnode ghcr.io/sentinel-official/dvpn-node:latest bash -c "process keys add ${USERNAME} --recover < $HOME/.sentinelnode/mnemonic.txt"
    rm ${HOME}/.sentinelnode/mnemonic.txt
fi

docker run \
    --detach \
    --volume ${HOME}/.sentinelnode:/root/.sentinelnode \
    --volume /lib/modules:/lib/modules \
    --cap-drop ALL \
    --cap-add NET_ADMIN \
    --cap-add NET_BIND_SERVICE \
    --cap-add NET_RAW \
    --cap-add SYS_MODULE \
    --sysctl net.ipv4.ip_forward=1 \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    --sysctl net.ipv6.conf.all.forwarding=1 \
    --sysctl net.ipv6.conf.default.forwarding=1 \
    --publish ${PUBLIC_PORT}:${PUBLIC_PORT}/tcp \
    --publish ${WIREGUARD_PORT}:${WIREGUARD_PORT}/udp \
    --name sentinel-dvpn-node-live \
    ghcr.io/sentinel-official/dvpn-node:latest bash -c "process start < ${HOME}/.sentinelnode/keyring_password.txt"
