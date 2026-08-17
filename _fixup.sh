for c in cyberorion_dvwa cyberorion_weak_ssh cyberorion_log4j cyberorion_vampi cyberorion_webgoat; do
  docker update --restart=always "$c" >/dev/null 2>&1 && echo "$c -> restart=always"
done
docker stop ia-backend ia-frontend docker-sandbox-1 >/dev/null 2>&1
docker ps --format '{{.Names}} {{.Status}}' | grep cyberorion
echo "--- memory ---"
free -h