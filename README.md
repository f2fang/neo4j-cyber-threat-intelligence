# Neo4j Cyber Threat Intelligence Project
 
## Project Overview
This project builds a graph-based Cyber Threat Intelligence (CTI) database using Neo4j. It ingests data from AlienVault OTX, organizes it into connected graph structures, and provides enhanced querying capabilities for threat analysis, IP lookups, domain relationships, and file hash analysis.
 
---
 
## Prerequisites
- Docker (latest version)
- Docker Compose
- Python 3.8+
- Neo4j Python Driver
 
You can install the Neo4j driver using:
```bash
pip3 install neo4j
pip3 install requests
```
 
---
 
## Project Structure
```
neo4j-cyber-threat-intelligence/
│
├── cypher/
│   ├── create_indexes.cypher         # Creates Range(B+ Tree)  indexes
│   ├── fulltext_indexes.cypher       # Builds fulltext indexes for URL, Domain, Hostname, FileHash
│   └── post_import_relations.cypher  # Establishes relationships and precomputes links
│
├── import_otx_to_neo4j_more_data.py  # Main script for data ingestion
├── check_otx_indicators_more.py      # Script to analyze indicator types and dataset size
│
├── docker-compose.yml                # Docker Compose file for easy setup
│
├── requirements.txt                  # Python dependencies
├── README.md                         # Project documentation (this file)
└── .env                              # Environment variables for Neo4j login
```
 
---
 
## Installation
 
### Environment Setup
1. **Create a `.env` file** in the root directory:
   ```bash
   touch .env
   ```

2. **Edit the `.env` file** and add the following configurations:
   ```env
   NEO4J_URI=bolt://localhost:7687
   NEO4J_USER=neo4j
   NEO4J_PASSWORD=password
   ```

3. **Save and close the file**.

---

4. **Clone the repository**:
   ```bash
   git clone https://github.com/f2fang/neo4j-cyber-threat-intelligence.git
   cd neo4j-cyber-threat-intelligence
   ```

5. **Install dependencies**:
   ```bash
   pip3 install -r requirements.txt
   ```
---
 
## Running Neo4j Docker Container
1. **Start the Docker container**:
   ```bash
   docker-compose up -d
   ```
 
2. **Access Neo4j Browser**:
    - URL: [http://localhost:7474](http://localhost:7474)
    - Username: `neo4j`
    - Password: `password`
    
3. **Verify the connection**:
   ```bash
   docker exec -it neo4j-cti cypher-shell -u neo4j -p password -d neo4j "RETURN 1 AS test;"
   ```
---
 
## Importing Data into Neo4j
 
## Checking Indicator Types and Dataset Size
To verify the types of indicators and the total dataset size, run:
```bash
python3 check_otx_indicators_more.py
```

You should see a breakdown of all indicators and the dataset volume.
 
---
 
To import data from AlienVault OTX, run:
```bash
python3 import_otx_to_neo4j_more_data.py
```
 
If you want to re-import, make sure to clear the database first:
```cypher
MATCH (n)
DETACH DELETE n;
```
 
---


## Create Indexing, and post-import relationships

1. Create indexes, fulltext indexes, and post-import relationships use the predefined Cyphers Scripts:
    ```bash
    docker exec -i neo4j-cti cypher-shell -u neo4j -p password < cypher/create_indexes.cypher
    docker exec -i neo4j-cti cypher-shell -u neo4j -p password < cypher/fulltext_indexes.cypher
    docker exec -i neo4j-cti cypher-shell -u neo4j -p password < cypher/post_import_relations.cypher
    ```
 
2. Verify the data:
    ```cypher
    // Verify Indexes
    CALL db.indexes;

    // Verify Data Import
    MATCH (p:Pulse) RETURN p LIMIT 5;
    MATCH (ip:IP) RETURN ip LIMIT 5;
    MATCH (d:Domain) RETURN d LIMIT 5;
    MATCH (u:URL) RETURN u LIMIT 5;
    MATCH (f:FileHash) RETURN f LIMIT 5;

    // Verify Relationships
    CALL db.relationshipTypes();

    // Verify Suspicious TLDs
    MATCH (n:SuspiciousTLD)
    RETURN labels(n)[0] AS Type, coalesce(n.url, n.name) AS Value
    LIMIT 5;

    // Verify Clustering and HotIP
    MATCH (c:Cluster)-[:CONTAINS]->(ip:HotIP)
    RETURN c.name AS Cluster, ip.address AS IP_Address
    LIMIT 5;

    // Verify IOC Associations
    MATCH (c:Cluster)-[:HAS_IOC]->(ioc)
    RETURN c.name AS Cluster, labels(ioc) AS IOC_Type, ioc
    LIMIT 5;
    ```
 
---
  
### Relationships Created:
1. **IP → Domain (RELATED_TO)**
    - Creates relationships between IP addresses and related ioc.
    - Cypher Query:
    ```cypher
    MATCH (ip:IP)-[:RELATED_TO]->(ioc)
RETURN ip.address AS IP, labels(ioc) AS Type, ioc LIMIT 5;
    ```
 
2. **URL → Hostname (HOSTED_ON)**
    - Links URLs to their respective hostnames.
    - Cypher Query:
    ```cypher
    MATCH (u:URL)-[:HOSTED_ON]->(h:Hostname)
    RETURN u, h LIMIT 5;
    ```
 
3. **FileHash → YARARule (MATCHES)**
    - Associates file hashes with YARA rules.
    - Cypher Query:
    ```cypher
    MATCH (f:FileHash)-[:MATCHES]->(y:YARARule)
    RETURN f, y LIMIT 5;
    ```
 
4. **Hostname → Domain (SUBDOMAIN_OF)**
    - Maps subdomains to their parent domains.
    - Cypher Query:
    ```cypher
   MATCH (h:Hostname)-[:SUBDOMAIN_OF]->(d:Domain)
RETURN h.name AS Subdomain, d.name AS ParentDomain
LIMIT 5;
    ```


 
These relationships are optimized for quick lookups and path traversal.
 
---
 
 
 
 
 
 
## Cleanup and Maintenance
To clear the database:
```cypher
MATCH (n)
DETACH DELETE n;
```
 
To restart Docker:
```bash
docker restart neo4j-cti
```
 
To check logs:
```bash
docker logs neo4j-cti
```
 
---
 
## Next Steps
- Add GDS (Graph Data Science) for threat prediction, implement GDS-based clustering for anomaly detection and threat grouping.
- Leverage `apoc.periodic.iterate` to keep relationships in sync.
- Implement real-time streaming with Kafka

---
 
**Happy Threat Hunting!** 🚀

## Member Contributions
 
- **Emanuel Baca**:
  - Co-designed and implemented Neo4j graph schemas
  - Developed Cypher queries for advanced threat analysis
  - Contributed to indexing strategies and performance tuning
  - Collaborated on data optimization and relationship building
 
- **Fang Fang**:
  - Co-designed and implemented Neo4j graph schemas
  - Developed Cypher queries for data import and relationship creation
  - GCP Test Environment setup and dataset import
  - Configured Docker Compose and Dockerfile for Neo4j deployment
  - Contributed to indexing strategies and performance tuning
  - Collaborated on data optimization and relationship building
 
 
---
