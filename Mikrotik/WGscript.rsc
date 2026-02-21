# Configure persistent Log
/system logging action
set 3 remote=xxx.xxx.xxx.xxx syslog-facility=syslog

/system logging
add action=remote disabled=no topics=account
add action=remote disabled=no topics=info


# Wireguard Online Status
/system script
add dont-require-permissions=no name=WGPeerStatus owner=admin policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source=":\
    local interfaceName \"Wireguard\"\r\
    \n\r\
    \n:global OfflinePeerList\r\
    \n:global OnlinePeerList\r\
    \n\r\
    \n:local OfflinePeerListTmp [ :toarray \"\" ]\r\
    \n:local OnlinePeerListTmp [ :toarray \"\" ]\r\
    \n\r\
    \n#:log info \"Avvio script per monitorare i peer dell'interfaccia \$inter\
    faceName\"\r\
    \n\r\
    \n:foreach peer in=[/interface wireguard peers find interface=\$interfaceN\
    ame] do={\r\
    \n    :set \$peerAddress [/interface wireguard peer get \$peer allowed-add\
    res]\r\
    \n    :set \$peerAddress  [:pick \$peerAddress 0 [:find \$peerAddress \"/\
    \"]]\r\
    \n    :local peerName [/interface wireguard peers get \$peer comment]\r\
    \n    :local remoteIpAddress [/interface wireguard peers get \$peer curren\
    t-endpoint-address]\r\
    \n\r\
    \n:if ( ([/interface wireguard peers get \$peer last-handshake] > 180) || \
    ([:len [/interface/wireguard/peers/get \$peer last-handshake]] = 0)) do={ \
    \r\
    \n               :if ( \$OfflinePeerList~\"\$peerAddress(;|\\\$)\" ) do={\
    \r\
    \n                   #:log info \"\$peerName - \$peerAddress still Offline\
    \"\r\
    \n                   :set OfflinePeerListTmp ( \$OfflinePeerListTmp, \$pee\
    rAddress );\r\
    \n                } else={\r\
    \n                    :log info \"wireguard user \$peerName logged out fro\
    m \$remoteIpAddress\"\r\
    \n                    :set OfflinePeerListTmp ( \$OfflinePeerListTmp, \$pe\
    erAddress );\r\
    \n                }\r\
    \n            } else {\r\
    \n              :if ( \$OnlinePeerList~\"\$peerAddress(;|\\\$)\" ) do={\r\
    \n                   #:log info \"\$peerName - \$peerAddress still Online\
    \"\r\
    \n                   :set OnlinePeerListTmp ( \$OnlinePeerListTmp, \$peerA\
    ddress );\r\
    \n                } else={\r\
    \n                    :log info \"wireguard user \$peerName logged in from\
    \_\$remoteIpAddress\"\r\
    \n                    :set OnlinePeerListTmp ( \$OnlinePeerListTmp, \$peer\
    Address );\r\
    \n                }\r\
    \n            }\r\
    \n}\r\
    \n\r\
    \n:set \$OfflinePeerList \$OfflinePeerListTmp\r\
    \n:set \$OnlinePeerList \$OnlinePeerListTmp"

/system scheduler
add interval=15s name=WGPeerCheck on-event="/system script run WGPeerStatus;" \
    policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon \
    start-date=2017-06-13 start-time=00:00:00
