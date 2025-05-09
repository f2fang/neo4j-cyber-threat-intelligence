// ==============================
// B+ Tree Range Indexes
// ==============================

// IP Address Index
CREATE RANGE INDEX ip_address_index IF NOT EXISTS FOR (ip:IP) ON (ip.address);

// Domain Name Index
CREATE RANGE INDEX domain_name_index IF NOT EXISTS FOR (d:Domain) ON (d.name);

// URL Index
CREATE RANGE INDEX url_index IF NOT EXISTS FOR (u:URL) ON (u.url);

// FileHash Index
CREATE RANGE INDEX filehash_index IF NOT EXISTS FOR (f:FileHash) ON (f.hash);

// Pulse ID Index
CREATE RANGE INDEX pulse_id_index IF NOT EXISTS FOR (p:Pulse) ON (p.id);

// CVE ID Index
CREATE RANGE INDEX cve_id_index IF NOT EXISTS FOR (c:CVE) ON (c.id);

// YARA Rule Index
CREATE RANGE INDEX yara_rule_index IF NOT EXISTS FOR (y:YARARule) ON (y.rule);

// Hostname Index
CREATE RANGE INDEX hostname_index IF NOT EXISTS FOR (h:Hostname) ON (h.name);

