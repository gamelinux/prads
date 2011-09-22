# essential for sniffing packets.
setcap cap_net_raw,cap_net_admin=eip prads
# for dropping privs.. might as well be root.
setcap cap_sys_chroot,cap_setuid,cap_setgid,cap_net_raw,cap_net_admin=eip prads

