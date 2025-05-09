// ==============================
// Establish Relationships
// ==============================

// IP → Domain (RESOLVES_TO)
CALL db.index.fulltext.queryNodes('domain_fulltext_index', '*') YIELD node AS domain
MATCH (ip:IP)
WHERE ip.address CONTAINS domain.name
MERGE (ip)-[:RESOLVES_TO]->(domain);

// URL → Hostname (HOSTED_ON)
CALL db.index.fulltext.queryNodes('url_fulltext_index', '*') YIELD node AS url
MATCH (hostname:Hostname)
WHERE url.url CONTAINS hostname.name
MERGE (url)-[:HOSTED_ON]->(hostname);

// FileHash → YARARule (MATCHES)
CALL db.index.fulltext.queryNodes('filehash_fulltext_index', '*') YIELD node AS hash
MATCH (yara:YARARule)
WHERE hash.hash CONTAINS yara.rule
MERGE (hash)-[:MATCHES]->(yara);

// IP → IOC (RELATED_TO)
MATCH (ip:IP)-[:ASSOCIATED_WITH]->(p:Pulse)<-[:ASSOCIATED_WITH]-(ioc)
MERGE (ip)-[:RELATED_TO]->(ioc);

// URL → IP (ASSOCIATED_WITH_IP)
MATCH (u:URL)-[:ASSOCIATED_WITH]->(p:Pulse)<-[:ASSOCIATED_WITH]-(ip:IP)
MERGE (u)-[:ASSOCIATED_WITH_IP]->(ip);

// URL → Domain (ASSOCIATED_WITH_DOMAIN)
MATCH (u:URL)-[:ASSOCIATED_WITH]->(p:Pulse)<-[:ASSOCIATED_WITH]-(d:Domain)
MERGE (u)-[:ASSOCIATED_WITH_DOMAIN]->(d);

// Hostname → Domain (SUBDOMAIN_OF)
CALL db.index.fulltext.queryNodes('hostname_fulltext_index', '*') YIELD node AS h
MATCH (d:Domain)
WHERE h.name CONTAINS d.name
MERGE (h)-[:SUBDOMAIN_OF]->(d);


// ==============================
// Additional Relationships
// ==============================

// URL → Hostname (CONTAINS_HOSTNAME)
CALL db.index.fulltext.queryNodes('url_fulltext_index', '*') YIELD node AS u
MATCH (h:Hostname)
WHERE u.url CONTAINS h.name
MERGE (u)-[:CONTAINS_HOSTNAME]->(h);

// URL → Domain (CONTAINS_DOMAIN)
CALL db.index.fulltext.queryNodes('url_fulltext_index', '*') YIELD node AS u
MATCH (d:Domain)
WHERE u.url CONTAINS d.name
MERGE (u)-[:CONTAINS_DOMAIN]->(d);

// Domain → Hostname (CONTAINS)
CALL db.index.fulltext.queryNodes('domain_fulltext_index', '*') YIELD node AS d
MATCH (h:Hostname)
WHERE h.name CONTAINS d.name
MERGE (d)-[:CONTAINS]->(h);

// Pulse → IOC (HAS_IOC)
MATCH (p:Pulse)-[:ASSOCIATED_WITH]->(ioc)
MERGE (p)-[:HAS_IOC]->(ioc);

// Pulse → Indicator Type (HAS_IOC_TYPE)
MATCH (p:Pulse)-[:ASSOCIATED_WITH]->(ioc)
WITH p, labels(ioc)[0] AS indicator_type
MERGE (p)-[:HAS_IOC_TYPE]->(:IndicatorType {name: indicator_type});

// FileHash → FileHash (SIMILAR_TO)
MATCH (f:FileHash)
WITH f.prefix5 AS prefix, collect(f) AS group
UNWIND group AS a
UNWIND group AS b
WITH a, b
WHERE id(a) < id(b) AND a.prefix5 = b.prefix5
MERGE (a)-[:SIMILAR_TO {method: "prefix5"}]->(b);

// ==============================
// Labeling
// ==============================

// ==============================
// Clustering
// ==============================


// Label HotIP
MATCH (ip:IP)-[:ASSOCIATED_WITH]->(p:Pulse)
WITH ip, count(p) AS pulse_count
WHERE pulse_count > 1
SET ip:HotIP;

// Create Cluster and Add IOC to Each Cluster
MATCH (ip:HotIP)-[:RELATED_TO]->(ioc)
WHERE any(l IN labels(ioc) WHERE l IN ['URL', 'Domain', 'FileHash', 'Hostname', 'CVE'])
MERGE (c:Cluster {cluster_type: "HotIP", name: "Cluster_" + ip.address})
MERGE (c)-[:CONTAINS]->(ip)
MERGE (c)-[:HAS_IOC]->(ioc);

// Label SuspiciousTLD for URL nodes
MATCH (u:URL)
WHERE NOT u.url ENDS WITH ".com"
  AND NOT u.url ENDS WITH ".net"
  AND NOT u.url ENDS WITH ".org"
SET u:SuspiciousTLD;

// Label SuspiciousTLD for Domain nodes
MATCH (d:Domain)
WHERE NOT d.name ENDS WITH ".com"
  AND NOT d.name ENDS WITH ".net"
  AND NOT d.name ENDS WITH ".org"
SET d:SuspiciousTLD;

// Label SuspiciousTLD for Hostname nodes
MATCH (h:Hostname)
WHERE NOT h.name ENDS WITH ".com"
  AND NOT h.name ENDS WITH ".net"
  AND NOT h.name ENDS WITH ".org"
SET h:SuspiciousTLD;

