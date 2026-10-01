# Ubuntu deployment

Deploy the application to `/var/www/black_falcon` and keep the protected
solution store outside the web project at
`/var/lib/black-falcon/solutions.json`.

## Service account and protected data

```bash
sudo useradd --system \
  --home /var/lib/black-falcon \
  --shell /usr/sbin/nologin \
  blackfalcon

sudo mkdir -p /var/lib/black-falcon
sudo cp /var/www/black_falcon/private/solutions.json \
  /var/lib/black-falcon/solutions.json
sudo chown blackfalcon:blackfalcon \
  /var/lib/black-falcon/solutions.json
sudo chmod 600 /var/lib/black-falcon/solutions.json
sudo rm -rf /var/www/black_falcon/private
```

## Application permissions

```bash
sudo chown -R blackfalcon:blackfalcon /var/www/black_falcon
sudo find /var/www/black_falcon -type d -exec chmod 755 {} \;
sudo find /var/www/black_falcon -type f -exec chmod 644 {} \;
sudo chmod 750 /var/www/black_falcon/database
sudo chmod 660 /var/www/black_falcon/database/black_falcon.db
sudo chmod 750 /var/www/black_falcon/instance
sudo chmod 660 /var/www/black_falcon/instance/soc_features.db
sudo mkdir -p /var/www/black_falcon/logs
sudo chown blackfalcon:blackfalcon /var/www/black_falcon/logs
```

## Python environment

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
cd /var/www/black_falcon
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Generate a session secret with `openssl rand -hex 32`. Copy
`deploy/black-falcon.env.example` to `/etc/black-falcon.env`, replace the secret
placeholder, then protect it:

```bash
sudo chown root:blackfalcon /etc/black-falcon.env
sudo chmod 640 /etc/black-falcon.env
```

Validate the installed application after the protected store and environment
file are in place:

```bash
set -a
source /etc/black-falcon.env
set +a
python3 validate_project.py
```

Remove generated Python caches before sealing the OVA:

```bash
find /var/www/black_falcon -type d -name "__pycache__" \
  -prune -exec rm -rf {} +
find /var/www/black_falcon -type f -name "*.pyc" -delete
```

## systemd

```bash
sudo cp deploy/black-falcon.service \
  /etc/systemd/system/black-falcon.service
sudo systemctl daemon-reload
sudo systemctl enable --now black-falcon
sudo systemctl status black-falcon
```

Follow service logs with:

```bash
journalctl -u black-falcon -f
```
