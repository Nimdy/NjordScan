# NjordScan Simulation Lab
.PHONY: demo build up down scan dast keystone clean logs arm disarm secrets

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

up: ## Start the vulnerable target services
	docker compose up -d web api
	@echo "web → http://localhost:3001   api → http://localhost:3002"

down: ## Stop and remove the lab
	docker compose down

scan: ## Static scan of every target through the containerized scanner
	docker compose run --rm njordscan scan /lab/targets/01-vulnerable-nextjs
	docker compose run --rm njordscan scan /lab/targets/03-supply-chain-attack
	docker compose run --rm njordscan scan /lab/targets/05-clean-app

dast: up ## Live DAST against the running services over the lab network
	docker compose run --rm njordscan scan /lab/targets/02-vulnerable-api --url http://api:3002 --allow-private
	docker compose run --rm njordscan scan /lab/targets/01-vulnerable-nextjs --url http://web:3001 --allow-private

keystone: ## The temporal demo — a commit that armed a pre-existing chain
	docker compose run --rm --entrypoint bash njordscan /lab/targets/04-keystone-repo/build-history.sh

logs: ## Tail the target services
	docker compose logs -f web api

clean: down ## Tear down + drop built images
	docker compose down --rmi local -v 2>/dev/null || true
