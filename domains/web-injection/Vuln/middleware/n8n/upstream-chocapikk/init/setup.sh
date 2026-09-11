#!/bin/bash

BASE_URL="http://127.0.0.1:5678"

echo "[*] Waiting for n8n..."
until curl -s "$BASE_URL/rest/settings" | grep -q versionCli; do
    sleep 2
done
echo "[+] n8n is ready"

echo "[*] Creating admin..."
curl -s -X POST "$BASE_URL/rest/owner/setup" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@exploit.local","firstName":"Admin","lastName":"Exploit","password":"ExploitLab123!"}'

echo -e "\n[*] Logging in..."
curl -s -X POST "$BASE_URL/rest/login" \
    -H "Content-Type: application/json" \
    -c /tmp/cookies.txt \
    -d '{"email":"admin@exploit.local","password":"ExploitLab123!"}'

echo -e "\n[*] Creating workflow..."
RESP=$(curl -s -X POST "$BASE_URL/rest/workflows" \
    -H "Content-Type: application/json" \
    -b /tmp/cookies.txt \
    -d '{
        "name": "Vulnerable Form",
        "nodes": [
            {
                "parameters": {
                    "formTitle": "Upload",
                    "responseMode": "responseNode",
                    "formFields": {"values": [{"fieldLabel": "document", "fieldType": "file", "requiredField": false}]}
                },
                "id": "trigger",
                "name": "Form Trigger",
                "type": "n8n-nodes-base.formTrigger",
                "typeVersion": 2.2,
                "position": [0, 0],
                "webhookId": "vulnerable-form"
            },
            {
                "parameters": {"respondWith": "binary", "inputDataFieldName": "document"},
                "id": "respond",
                "name": "Respond",
                "type": "n8n-nodes-base.respondToWebhook",
                "typeVersion": 1.1,
                "position": [300, 0]
            }
        ],
        "connections": {"Form Trigger": {"main": [[{"node": "Respond", "type": "main", "index": 0}]]}},
        "active": false,
        "settings": {"executionOrder": "v1"}
    }')

ID=$(echo "$RESP" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "[+] Workflow ID: $ID"

echo "[*] Activating..."
curl -s -X PATCH "$BASE_URL/rest/workflows/$ID" \
    -H "Content-Type: application/json" \
    -b /tmp/cookies.txt \
    -d '{"active": true}'

echo -e "\n"
echo "=========================================="
echo "[+] Lab ready!"
echo "[+] Form: http://localhost:5678/form/vulnerable-form"
echo "[+] Version: 1.65.0 (VULNERABLE)"
echo "=========================================="
