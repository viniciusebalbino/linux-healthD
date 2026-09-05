#!/bin/sh
# healthD — instala em /usr/linux-healthd e registra o serviço systemd "healthd".
set -eu

PREFIX=/usr/linux-healthd
UNIT=/etc/systemd/system/healthd.service
CONF=/etc/linux-healthd.conf
STATE=/var/lib/healthd
SERVICE_USER=healthd

log() { printf '%s\n' "$*"; }
die() { printf 'erro: %s\n' "$*" >&2; exit 1; }

need_root() {
  [ "$(id -u)" -eq 0 ] || die "rode como root: sudo sh install.sh"
}

source_dir() {
  if [ -f ./healthd.py ] && [ -d ./web ]; then
    pwd
    return
  fi
  ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
  [ -f "$ROOT/healthd.py" ] && [ -d "$ROOT/web" ] || die "não achei healthd.py/web nesta pasta nem ao lado do install.sh"
  printf '%s\n' "$ROOT"
}

python_ok() {
  cmd=$1
  command -v "$cmd" >/dev/null 2>&1 || return 1
  "$cmd" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1
}

find_python() {
  for cmd in python3 python python3.14 python3.13 python3.12 python3.11 python3.10 \
             python3.9 python3.8 py python3.15; do
    if python_ok "$cmd"; then
      command -v "$cmd"
      return 0
    fi
  done
  if command -v python3 >/dev/null 2>&1; then
    python3 -V >&2 || true
  fi
  die "precisa de Python 3.10+ (python3, python, python3.12…)"
}

pkg_install() {
  # tenta o pacote de venv/pip da distro, se o venv padrão falhar
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y python3 python3-venv python3-pip || apt-get install -y python3-pip
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 python3-pip python3-venv || dnf install -y python3 python3-pip
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 python3-pip
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install python3 python3-pip python3-venv || \
      zypper --non-interactive install python3 python3-pip
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm python python-pip
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache python3 py3-pip py3-virtualenv || apk add --no-cache python3 py3-pip
  elif command -v xbps-install >/dev/null 2>&1; then
    xbps-install -Sy python3 python3-pip
  else
    return 1
  fi
}

ensure_venv() {
  PY=$1
  VENV=$PREFIX/.venv
  if [ -x "$VENV/bin/python" ]; then
    log "venv já existe: $VENV"
    return 0
  fi
  log "criando env Python em $VENV"
  if "$PY" -m venv "$VENV" 2>/dev/null; then
    return 0
  fi
  log "módulo venv ausente — tentando instalar python3-venv/pip da distro"
  pkg_install || true
  PY=$(find_python)
  if "$PY" -m venv "$VENV" 2>/dev/null; then
    return 0
  fi
  if command -v virtualenv >/dev/null 2>&1; then
    virtualenv -p "$PY" "$VENV" && return 0
  fi
  return 1
}

ensure_pip() {
  VPY=$1
  if "$VPY" -m pip --version >/dev/null 2>&1; then
    return 0
  fi
  log "pip ausente no env — tentando ensurepip"
  if "$VPY" -m ensurepip --upgrade >/dev/null 2>&1; then
    return 0
  fi
  TMP=$(mktemp)
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL https://bootstrap.pypa.io/get-pip.py -o "$TMP" || rm -f "$TMP"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP" https://bootstrap.pypa.io/get-pip.py || rm -f "$TMP"
  fi
  if [ -s "$TMP" ]; then
    "$VPY" "$TMP" && rm -f "$TMP" && return 0
  fi
  rm -f "$TMP"
  return 1
}

copy_tree() {
  ROOT=$1
  log "copiando de $ROOT para $PREFIX"
  mkdir -p "$PREFIX/web/assets"
  cp -a "$ROOT/healthd.py" "$PREFIX/healthd.py"
  chmod 755 "$PREFIX/healthd.py"
  cp -a "$ROOT/web/." "$PREFIX/web/"
  [ -f "$ROOT/README.md" ] && cp -a "$ROOT/README.md" "$PREFIX/"
  [ -f "$ROOT/LICENSE" ] && cp -a "$ROOT/LICENSE" "$PREFIX/"
  [ -f "$ROOT/requirements.txt" ] && cp -a "$ROOT/requirements.txt" "$PREFIX/"
  [ -f "$ROOT/install.sh" ] && cp -a "$ROOT/install.sh" "$PREFIX/"
  find "$PREFIX" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
  find "$PREFIX" -type f -name '*.pyc' -delete 2>/dev/null || true
}

ensure_user() {
  if id "$SERVICE_USER" >/dev/null 2>&1; then
    :
  elif command -v useradd >/dev/null 2>&1; then
    useradd -r -M -d "$STATE" -s /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null \
      || useradd -r -d "$STATE" -s /bin/false "$SERVICE_USER" \
      || return 1
  elif command -v adduser >/dev/null 2>&1; then
    adduser -S -H -h "$STATE" -s /sbin/nologin "$SERVICE_USER" 2>/dev/null \
      || adduser --system --no-create-home --home "$STATE" --shell /usr/sbin/nologin "$SERVICE_USER" \
      || return 1
  else
    return 1
  fi
  if getent group systemd-journal >/dev/null 2>&1; then
    if command -v usermod >/dev/null 2>&1; then
      usermod -aG systemd-journal "$SERVICE_USER" 2>/dev/null || true
    elif command -v adduser >/dev/null 2>&1; then
      adduser "$SERVICE_USER" systemd-journal 2>/dev/null || true
    fi
  fi
  mkdir -p "$STATE"
  chown -R "$SERVICE_USER:$SERVICE_USER" "$STATE" 2>/dev/null || chown -R "$SERVICE_USER" "$STATE" || true
  return 0
}

write_run() {
  PYBIN=$1
  cat > "$PREFIX/run-healthd" <<EOF
#!/bin/sh
set -eu
PREFIX=$PREFIX
HOST=127.0.0.1
PORT=9999
[ -f $CONF ] && . $CONF
exec "$PYBIN" "\$PREFIX/healthd.py" --host "\${HEALTHD_HOST:-\$HOST}" --port "\${HEALTHD_PORT:-\$PORT}"
EOF
  chmod 755 "$PREFIX/run-healthd"
}

write_conf() {
  if [ -f "$CONF" ]; then
    log "mantendo $CONF"
    return
  fi
  cat > "$CONF" <<'EOF'
# healthD — altere e rode: systemctl restart healthd
HEALTHD_HOST=127.0.0.1
HEALTHD_PORT=9999
EOF
  chmod 644 "$CONF"
}

write_unit() {
  RUNUSER=$1
  EXTRA_GROUP=
  if [ "$RUNUSER" = "$SERVICE_USER" ] && getent group systemd-journal >/dev/null 2>&1; then
    EXTRA_GROUP="SupplementaryGroups=systemd-journal"
  fi
  cat > "$UNIT" <<EOF
[Unit]
Description=healthD — painel de saúde da máquina
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUNUSER
$EXTRA_GROUP
WorkingDirectory=$PREFIX
Environment=HOME=$STATE
Environment=XDG_CONFIG_HOME=$STATE/.config
ExecStart=$PREFIX/run-healthd
Restart=on-failure
RestartSec=3
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
}

main() {
  need_root
  command -v systemctl >/dev/null 2>&1 || die "este instalador usa systemd (systemctl não encontrado)"
  ROOT=$(source_dir)
  PY=$(find_python)
  case $PY in
    /*) ;;
    *) PY=$(command -v "$PY") ;;
  esac
  log "Python: $PY ($($PY -V 2>&1))"

  if systemctl is-active --quiet healthd.service 2>/dev/null; then
    log "parando healthd para atualizar arquivos"
    systemctl stop healthd.service || true
  fi

  copy_tree "$ROOT"

  PYBIN=$PY
  if ensure_venv "$PY"; then
    PYBIN=$PREFIX/.venv/bin/python
    [ -x "$PYBIN" ] || die "venv criado, mas sem interpretador em $PYBIN"
    if [ -f "$PREFIX/requirements.txt" ]; then
      ensure_pip "$PYBIN" || die "não foi possível obter pip para instalar requirements.txt"
      log "instalando dependências do requirements.txt"
      "$PYBIN" -m pip install --upgrade pip
      "$PYBIN" -m pip install -r "$PREFIX/requirements.txt"
    else
      log "sem requirements.txt — healthD só usa a biblioteca padrão; env isolado mesmo assim"
    fi
  else
    if [ -f "$ROOT/requirements.txt" ] || [ -f "$PREFIX/requirements.txt" ]; then
      die "há requirements.txt, mas não deu para criar o env Python (instale python3-venv / python3-pip e rode de novo)"
    fi
    log "venv indisponível — usando o Python do sistema: $PYBIN"
  fi

  write_run "$PYBIN"
  write_conf

  RUNUSER=root
  if ensure_user; then
    RUNUSER=$SERVICE_USER
    chown -R "$SERVICE_USER:$SERVICE_USER" "$PREFIX" 2>/dev/null || chown -R "$SERVICE_USER" "$PREFIX" || true
    log "serviço vai rodar como $SERVICE_USER"
  else
    log "não criou usuário $SERVICE_USER — serviço como root (acesso total ao journal)"
  fi

  write_unit "$RUNUSER"
  systemctl daemon-reload
  systemctl enable healthd.service
  systemctl start healthd.service
  if systemctl is-active --quiet healthd.service; then
    log "healthD instalado e ativo"
    log "painel: http://127.0.0.1:9999  (host/porta em $CONF)"
    log "status: systemctl status healthd"
  else
    systemctl status healthd.service --no-pager -l || true
    die "o serviço foi criado, mas não subiu — veja journalctl -u healthd"
  fi
}

main "$@"
