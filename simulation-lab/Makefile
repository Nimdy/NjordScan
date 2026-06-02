# NjordScan Simulation Lab
.PHONY: demo build up down scan dast keystone clean logs arm disarm secrets redteam blueteam purple pivot dashboard predict byo sigma

DASH_PORT := $(or $(DASH_HOST_PORT),8088)

redteam: up ## Red team: actually exploit the live targets over the lab network
	@sleep 2
	docker compose run --rm --build redteam

blueteam: ## Blue team: detect the attacks in the targets' access logs (one-shot)
	docker compose run --rm --build blueteam --once

sigma: ## Export the blue-team detections as portable Sigma rules (blueteam/sigma/*.yml)
	python3 blueteam/gen-sigma.py

pivot: up ## Lateral movement: the attacker pivots through the web RCE to the SEGMENTED internal tier
	@sleep 3
	-docker run --rm -v "$(CURDIR)/logs:/x" alpine sh -c 'rm -f /x/*.log /x/redteam.jsonl' 2>/dev/null
	@printf '\n\033[1;31m== RED TEAM — no route to the internal tier, so pivot THROUGH the web RCE ==\033[0m\n'
	-docker compose run --rm --build redteam
	@printf '\n\033[1;34m== BLUE TEAM — the pivot landing on the internal datastore, seen in the logs ==\033[0m\n'
	docker compose run --rm --build blueteam --once
	@printf '\n\033[1;32mThe internal tier is unreachable from the attacker box — yet the web foothold reached the crown jewels, and the blue team saw it.\033[0m\n'

byo: ## Purple loop against YOUR OWN target:  make byo TARGET_URL=http://host.docker.internal:3000
	@[ -n "$(TARGET_URL)" ] || { printf '\033[1;31mSet TARGET_URL (an app you own/are authorized to test), e.g.:\033[0m\n  make byo TARGET_URL=http://host.docker.internal:3000\n  make byo TARGET_URL=https://staging.yourapp.com\n'; exit 1; }
	-docker run --rm -v "$(CURDIR)/logs:/x" alpine sh -c 'rm -f /x/*.log /x/redteam.jsonl /x/predict.json' 2>/dev/null
	TARGET_URL="$(TARGET_URL)" docker compose up -d --build byo-proxy dashboard
	@sleep 2
	@printf '\n\033[1;35m== 1. NjordScan PREDICTS — DAST scan of your target (via the proxy) ==\033[0m\n'
	-docker compose run --rm --build njordscan scan /lab/byo-proxy/empty-target --url http://byo-proxy:8080 --allow-private
	-docker compose run --rm njordscan scan /lab/byo-proxy/empty-target --url http://byo-proxy:8080 --allow-private --format json -o /lab/logs/predict.json
	@printf '\n\033[1;31m== 2. RED TEAM — generic web attacks on YOUR app (through the proxy) ==\033[0m\n'
	-docker compose run --rm --build --entrypoint /redteam/attack-byo.sh -e BASE_URL=http://byo-proxy:8080 redteam
	@printf '\n\033[1;34m== 3. BLUE TEAM — what it detected in your app traffic ==\033[0m\n'
	docker compose run --rm --build blueteam --once
	@printf '\n\033[1;32mNjordScan predicted, the attacker probed YOUR app, and the blue team caught every attempt.\033[0m\n'
	@printf '\033[1;35m📊 See it all on the dashboard → http://localhost:%s\033[0m\n' "$(DASH_PORT)"

purple: up ## Full purple loop — NjordScan predicts, red team proves, blue team detects
	@sleep 3
	-docker run --rm -v "$(CURDIR)/logs:/x" alpine sh -c 'rm -f /x/*.log /x/redteam.jsonl /x/predict.json' 2>/dev/null
	@printf '\n\033[1;35m== 1. NjordScan PREDICTS — the attack paths waiting in the target ==\033[0m\n'
	-docker compose run --rm --build njordscan scan /lab/targets/02-vulnerable-api
	-docker compose run --rm njordscan scan /lab/targets/01-vulnerable-nextjs --format json -o /lab/logs/predict.json
	@printf '\n\033[1;31m== 2. RED TEAM PROVES — exploiting the live targets for real ==\033[0m\n'
	-docker compose run --rm --build redteam
	@printf '\n\033[1;34m== 3. BLUE TEAM DETECTS — what the defenders saw in the logs ==\033[0m\n'
	docker compose run --rm --build blueteam --once
	@printf '\n\033[1;32mThe same traffic NjordScan predicted, the red team executed, and the blue team caught.\033[0m\n'
	@printf '\033[1;35m📊 See it all on the dashboard → http://localhost:%s\033[0m\n' "$(DASH_PORT)"

arm: ## Inject real-FORMAT fake provider keys for the full demo (DO NOT COMMIT)
	python3 ../scripts/lab-secrets.py arm

disarm: ## Restore the pushable placeholder secrets (run before committing)
	python3 ../scripts/lab-secrets.py disarm

secrets: ## Show whether the demo secrets are armed or disarmed
	python3 ../scripts/lab-secrets.py status

demo: ## Build everything, run every scan, capture reports (the full show)
	./run-lab.sh

build: ## Build the scanner + target images
	docker compose build

up: ## Start the target services (incl. segmented internal tier) + the dashboard + C2
	docker compose up -d web api internal dashboard c2
	@echo "web → http://localhost:3001   api → http://localhost:3002   internal → segmented (no host port)"
	@printf '\033[1;35m📊 dashboard → http://localhost:%s\033[0m\n' "$(DASH_PORT)"

dashboard: ## Build + open the purple web dashboard (live; feed it with make purple/redteam/pivot)
	docker compose up -d --build web api internal dashboard
	-$(MAKE) predict
	@printf '\n\033[1;35m🛡️  Purple dashboard is live → http://localhost:%s\033[0m\n' "$(DASH_PORT)"
	@printf '   Generate activity with: make purple   (or make redteam / make pivot)\n'

predict: ## Refresh the dashboard's "predicted" column (NjordScan static scan -> logs/predict.json)
	-docker compose run --rm --build njordscan scan /lab/targets/01-vulnerable-nextjs --format json -o /lab/logs/predict.json

down: ## Stop and remove the lab
	docker compose down

scan: ## Static scan of every target through the containerized scanner
	docker compose run --rm njordscan scan /lab/targets/01-vulnerable-nextjs
	docker compose run --rm njordscan scan /lab/targets/03-supply-chain-attack
	docker compose run --rm njordscan scan /lab/targets/05-clean-app
	docker compose run --rm njordscan scan /lab/targets/06-internal-admin

dast: up ## Live DAST against the running services over the lab network
	docker compose run --rm njordscan scan /lab/targets/02-vulnerable-api --url http://api:3002 --allow-private
	docker compose run --rm njordscan scan /lab/targets/01-vulnerable-nextjs --url http://web:3001 --allow-private

keystone: ## The temporal demo — a commit that armed a pre-existing chain
	docker compose run --rm --entrypoint bash njordscan /lab/targets/04-keystone-repo/build-history.sh

logs: ## Tail the target services
	docker compose logs -f web api

clean: down ## Tear down + drop built images
	docker compose down --rmi local -v 2>/dev/null || true
