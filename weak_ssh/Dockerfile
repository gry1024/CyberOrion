FROM alpine:3.18
RUN apk add --no-cache openssh bash sudo && \
    ssh-keygen -A && \
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    echo 'UseDNS no' >> /etc/ssh/sshd_config && \
    echo 'LogLevel VERBOSE' >> /etc/ssh/sshd_config && \
    adduser -D -s /bin/bash user && echo 'user:user' | chpasswd && \
    adduser -D -s /bin/bash admin && echo 'admin:admin123' | chpasswd && \
    adduser -D -s /bin/bash ctf && echo 'ctf:ctf' | chpasswd && \
    mkdir -p /home/ctf && \
    echo 'FLAG{weak_ssh_brute_force_is_easy}' > /home/ctf/flag.txt && \
    chmod 444 /home/ctf/flag.txt
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-E", "/var/log/sshd.log"]