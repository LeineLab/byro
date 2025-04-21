docker compose -p byro build
docker compose -p byro stop
docker compose -p byro rm gunicorn
docker compose -p byro rm manage
docker compose -p byro up -d
