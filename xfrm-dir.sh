set -eu
ip x s f
/home/a/git/iproute2/ip/ip xfrm state add src 10.1.3.2 dst 10.1.2.1 proto esp spi 2 flag icmp reqid 2 replay-window 10 mode tunnel dir out aead 'rfc4106(gcm(aes))' 0x2222222222222222222222222222222222222222 96 if_id 11 offload dev eth1 dir in 2>/dev/null && R="[FAIL]" || export R="[PASS]"
echo "$R : Mismatched dir and offload dir out"

/home/a/git/iproute2/ip/ip xfrm state add src 10.1.3.2 dst 10.1.2.1 proto esp spi 2 flag icmp reqid 2 replay-window 10 mode tunnel dir in aead 'rfc4106(gcm(aes))' 0x2222222222222222222222222222222222222222 96 if_id 11 offload dev eth1 dir out 2>/dev/null && export R="[FAIL]" || export R="[PASS]"
echo "$R : Mismatched dir and offload dir in"

/home/a/git/iproute2/ip/ip xfrm state add src 10.1.3.2 dst 10.1.2.1 proto esp spi 2 flag icmp reqid 2 replay-window 10 mode tunnel dir out aead 'rfc4106(gcm(aes))' 0x2222222222222222222222222222222222222222 96 if_id 11 && export R="[PASS]" || export R="[FAIL]"
echo "$R : Add dir out : $R"
(/home/a/git/iproute2/ip/ip x s | grep "dir out" > /dev/null) && export R="[PASS]" || export R="[FAIL]"
echo "$R : Add dir out output"

/home/a/git/iproute2/ip/ip xfrm state add src 10.1.3.4 dst 10.1.2.3 proto esp spi 3 flag icmp reqid 2 replay-window 10 mode tunnel dir in aead 'rfc4106(gcm(aes))' 0x2222222222222222222222222222222222222222 96 if_id 11 && export R="[PASS]" || export R="[FAIL]"
(/home/a/git/iproute2/ip/ip x s | grep "dir out" > /dev/null) && export R="[PASS]" || export R="[FAIL]"
echo "$R : Add dir in output"
