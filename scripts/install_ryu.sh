#!/bin/bash
# Installs Ryu 4.34 into ~/aegis-venv on Ubuntu 22.04 / Python 3.10.
# Verified working recipe (Oct 2026):
#   1. Ryu's old setup.py needs setuptools<58 + pbr, built without isolation,
#      and PBR_VERSION set (the sdist has no git metadata).
#   2. eventlet 0.30.2 (Ryu's usual pin) crashes on Python 3.10, so use 0.33.3
#      with dnspython 2.2.1.
#   3. eventlet 0.33 removed ALREADY_HANDLED, so patch ryu/app/wsgi.py.
set -e
VENV="$HOME/aegis-venv"
[ -d "$VENV" ] || python3 -m venv "$VENV"
source "$VENV/bin/activate"
pip install -q --upgrade pip
pip install -q "setuptools<58" wheel pbr
PBR_VERSION=4.34 pip install -q --no-build-isolation ryu==4.34
pip install -q eventlet==0.33.3 dnspython==2.2.1
pip install -q -r "$(dirname "$0")/../requirements.txt"
python "$(dirname "$0")/patch_ryu.py"
bash "$(dirname "$0")/check_env.sh"
