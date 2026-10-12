#!/usr/bin/env bash
set -euo pipefail

APP="/var/www/html"

if [[ -f "${APP}/config.php" ]] && grep -q DIR_OPENCART "${APP}/config.php"; then
  echo "IOC opencart-already-installed"
  chown -R www-data:www-data "${APP}/system/storage" "${APP}/image" || true
  exit 0
fi

echo "IOC opencart-cli-install"
cp -n "${APP}/config-dist.php" "${APP}/config.php"
cp -n "${APP}/admin/config-dist.php" "${APP}/admin/config.php"
php "${APP}/install/cli_install.php" install \
  --username admin \
  --password LabPass123! \
  --email lab@localhost.invalid \
  --http_server http://127.0.0.1:18108/ \
  --language en-gb \
  --db_driver mysqli \
  --db_hostname mysql \
  --db_username root \
  --db_password opencart \
  --db_database opencart \
  --db_port 3306 \
  --db_prefix oc_
php -r '
$m=new mysqli("mysql","root","opencart","opencart");
if ($m->connect_error) { fwrite(STDERR, $m->connect_error); exit(1); }
// Demo iPod Nano (36): already shipping=0 and points=100. Drop tax so reward can zero getTotals exactly.
$m->query("UPDATE oc_product SET shipping=0, tax_class_id=0, points=100, status=1 WHERE product_id=36");
$hash=password_hash("LabPass123!", PASSWORD_DEFAULT);
$m->query("DELETE FROM oc_customer WHERE email=\"oc-reward@localhost.invalid\"");
$m->query("INSERT INTO oc_customer (customer_group_id,store_id,language_id,firstname,lastname,email,telephone,password,custom_field,newsletter,ip,status,safe,commenter,token,code,date_added) VALUES (1,0,1,\"Reward\",\"Buyer\",\"oc-reward@localhost.invalid\",\"5550100\",\"".$m->real_escape_string($hash)."\",\"\",0,\"127.0.0.1\",1,0,0,\"\",\"\",NOW())");
$cid=(int)$m->insert_id;
$m->query("INSERT INTO oc_customer_reward (customer_id,order_id,description,points,date_added) VALUES ($cid,0,\"lab seed\",1000,NOW())");
echo "IOC customer_id=$cid points=1000 product_36_points=100\n";
'
chown -R www-data:www-data \
  "${APP}/system/storage" \
  "${APP}/image" \
  "${APP}/config.php" \
  "${APP}/admin/config.php" \
  || true
echo "IOC opencart-setup-done"
