#!/bin/bash

# tar czvPf /root/postgresql14.tgz \
# 	/etc/profile.d/postgresql.sh \
# 	/etc/ld.so.conf.d/postgres.conf \
# 	/etc/default/postgresql \
# 	/var/lib/postgres/ \
# 	/var/log/pgbackrest/ \
# 	/etc/logrotate.d/pgbackrest \
# 	/etc/systemd/system/postgresql.service \
# 	/etc/systemd/system/postgresql_prereq.service \
# 	/usr/local/postgresql \
# 	/usr/local/postgresql-14.8 \
# 	/usr/local/pgbackrest \
# 	/usr/local/pgbackrest-2.46/


# SCRIPT_LEN=$(egrep -n '^exit 0$' $0 | awk -F: '{print $1}')
# TGZ_START=$((SCRIPT_LEN + 1))
TGZ_START=94
tail +${TGZ_START} $0 | tar xzvPf - 

ldconfig

getent group postgres
if [[ $? -ne 0 ]]; then
  groupadd -g 32 -r postgres
fi

getent passwd postgres
if [[ $? -ne 0 ]]; then
  # useradd -r -c 'postgres database user' -s /bin/bash -g 32 -u 32 -m -k /etc/skel -d /var/lib/postgres postgres
  GROUP_ID=$(getent group postgres|awk -F: '{print $3}')
  useradd -r -c 'postgres database user' -s /bin/bash -g ${GROUP_ID} -u 32 -d /var/lib/postgres postgres
fi

apt-get -y update
apt-get -y upgrade
apt-get -y install build-essential libxml2-dev libyaml-dev libbz2-dev libssl-dev pkg-config fdisk locales rsync screen sysstat strace vim
sed -i 's/^" \(let g:skip_defaults_vim.*\)/\1/g' /etc/vim/vimrc
sed -i 's/^# \(en_US.*\)/\1/g'  /etc/locale.gen
sed -i 's/^LANG=.*/LANG=en_US.UTF-8/g' /etc/default/locale
locale-gen

egrep '^tmpfs' /etc/fstab | awk '{print $2}' | egrep -q '^/dbdata-ramdisk'
if [[ $? -ne 0 ]]; then
    mkdir -p /dbdata-ramdisk
    cat <<EOF >> /etc/fstab
tmpfs		/dbdata-ramdisk		tmpfs	size=64M,mode=0700,uid=postgres,gid=postgres	0 0
# LABEL=pgdata	/var/lib/postgres/data/	ext4	noatime						0 0
# LABEL=pgts1	/var/lib/postgres/ts1/	ext4	noatime						0 0
EOF
    systemctl enable postgresql_prereq
fi

test -f /lib/systemd/system/google-cloud-ops-agent.service
if [[ $? -ne 0 ]]; then
    cd /tmp
    curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
    bash add-google-cloud-ops-agent-repo.sh --also-install

    cat <<EOF >> /etc/google-cloud-ops-agent/config.yaml
logging:
  receivers:
    syslog:
      type: files
      include_paths:
      - /var/log/messages
      - /var/log/syslog
  service:
    pipelines:
      default_pipeline:
        receivers: [syslog]
metrics:
  receivers:
    hostmetrics:
      type: hostmetrics
      collection_interval: 30s
  processors:
    metrics_filter:
      type: exclude_metrics
      metrics_pattern: []
  service:
    pipelines:
      default_pipeline:
        receivers: [hostmetrics]
        processors: [metrics_filter]
EOF
    systemctl restart google-cloud-ops-agent
    PAGER=cat systemctl status google-cloud-ops-agent
fi

exit 0
