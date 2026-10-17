# Shodan - Databases
A curated collection of Shodan search queries for discovering and researching publicly observable database services during authorized security research and reconnaissance.

---

# Database Services
## MySQL
port:3306

## PostgreSQL
port:5432

## Microsoft SQL Server
port:1433

## MongoDB
port:27017

## Redis
port:6379

## Elasticsearch
port:9200

## Cassandra
port:9042

## Oracle Database
port:1521

---

# MySQL
## MySQL Services
port:3306

## MySQL by Organization
org:"Example Organization" port:3306

## MySQL by Country
country:US port:3306

## MySQL Product Search
product:"MySQL"

---

# PostgreSQL
## PostgreSQL Services
port:5432

## PostgreSQL by Organization
org:"Example Organization" port:5432

## PostgreSQL by Country
country:US port:5432

## PostgreSQL Product Search
product:"PostgreSQL"

---

# Microsoft SQL Server
## MSSQL Services
port:1433

## MSSQL by Organization
org:"Example Organization" port:1433

## MSSQL by Country
country:US port:1433

## Microsoft SQL Server Product Search
product:"Microsoft SQL Server"

---

# MongoDB
## MongoDB Services
port:27017

## MongoDB by Organization
org:"Example Organization" port:27017

## MongoDB by Country
country:US port:27017

## MongoDB Product Search
product:"MongoDB"

---

# Redis
## Redis Services
port:6379

## Redis by Organization
org:"Example Organization" port:6379

## Redis by Country
country:US port:6379

## Redis Product Search
product:"Redis"

---

# Elasticsearch
## Elasticsearch Services
port:9200

## Elasticsearch by Organization
org:"Example Organization" port:9200

## Elasticsearch by Country
country:US port:9200

## Elasticsearch Product Search
product:"Elasticsearch"

---

# Cassandra
## Cassandra Services
port:9042

## Cassandra by Organization
org:"Example Organization" port:9042

## Cassandra by Country
country:US port:9042

## Cassandra Product Search
product:"Cassandra"

---

# Oracle
## Oracle Database Services
port:1521

## Oracle by Organization
org:"Example Organization" port:1521

## Oracle by Country
country:US port:1521

## Oracle Product Search
product:"Oracle"

---

# Database Discovery by Organization
## Common Database Ports
org:"Example Organization" (port:3306 OR port:5432 OR port:1433 OR port:27017 OR port:6379 OR port:9200)

## Relational Databases
org:"Example Organization" (port:3306 OR port:5432 OR port:1433 OR port:1521)

## NoSQL Databases
org:"Example Organization" (port:27017 OR port:6379 OR port:9200 OR port:9042)

---

# Database Discovery by Country
## Common Database Ports
country:US (port:3306 OR port:5432 OR port:1433 OR port:27017 OR port:6379 OR port:9200)

## Relational Databases
country:US (port:3306 OR port:5432 OR port:1433 OR port:1521)

## NoSQL Databases
country:US (port:27017 OR port:6379 OR port:9200 OR port:9042)

---

# Database Technology Research
## MySQL
product:"MySQL"

## PostgreSQL
product:"PostgreSQL"

## MongoDB
product:"MongoDB"

## Redis
product:"Redis"

## Elasticsearch
product:"Elasticsearch"

## Cassandra
product:"Cassandra"

---

# Version Research
## MySQL Version
product:"MySQL" version:"version"

## PostgreSQL Version
product:"PostgreSQL" version:"version"

## MongoDB Version
product:"MongoDB" version:"version"

## Redis Version
product:"Redis" version:"version"

## Elasticsearch Version
product:"Elasticsearch" version:"version"

---

# Database Reconnaissance Workflow
1. Start with the authorized organization or network.
2. Identify publicly observable database services.
3. Determine the database technology when available.
4. Record ports, products and versions as reconnaissance data.
5. Correlate discovered services with the authorized security scope.
6. Validate findings using approved testing methods.
7. Report unintended exposure according to the applicable security policy.

---

# Important Notes
- A database service being visible on the internet does not automatically indicate a vulnerability.
- Shodan results may be outdated.
- Product and version information should be manually verified.
- Do not attempt unauthorized authentication or database access.
- Do not retrieve, modify or delete data from discovered services.
- Do not perform brute-force attacks.
- Only test database services when explicit authorization exists.
- Respect bug bounty scope and program rules.
- These queries are intended for educational purposes, OSINT and authorized security research.