FROM vpnctl-helper-builder:x86_64-rust1.97.1
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server sudo python3 \
    && rm -rf /var/lib/apt/lists/* && rm -f /etc/ssh/ssh_host_* \
    && useradd -m -s /bin/bash testuser && passwd -d testuser \
    && printf 'testuser ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/testuser && chmod 0440 /etc/sudoers.d/testuser
ENTRYPOINT ["/bin/bash", "/fixture/entrypoint.sh"]
