// ==============================
// Fulltext Indexes for Search
// ==============================

// URL Fulltext Index
CREATE FULLTEXT INDEX url_fulltext_index IF NOT EXISTS FOR (u:URL) ON EACH [u.url];

// Domain Fulltext Index
CREATE FULLTEXT INDEX domain_fulltext_index IF NOT EXISTS FOR (d:Domain) ON EACH [d.name];

// Hostname Fulltext Index
CREATE FULLTEXT INDEX hostname_fulltext_index IF NOT EXISTS FOR (h:Hostname) ON EACH [h.name];

// Non-Common TLD Fulltext Index
CREATE FULLTEXT INDEX non_common_tld_index IF NOT EXISTS FOR (n:URL|Domain|Hostname) ON EACH [n.url, n.name];

// FileHash Fulltext Index
CREATE FULLTEXT INDEX filehash_fulltext_index IF NOT EXISTS FOR (f:FileHash) ON EACH [f.hash];
