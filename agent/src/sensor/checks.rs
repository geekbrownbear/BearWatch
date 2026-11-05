//! Proton's configuration checks ("PIS-xxxx").
//!
//! Adapted from Proton IP Scanner (https://github.com/geekbrownbear/proton-network-scanner), GPL-3.0-or-later.
//! Ids, titles, CVSS v4.0 base scores and solutions are Proton's, unchanged,
//! so a finding means the same thing in both tools. Proton's descriptions and priority inputs
//! are left out: the server owns presentation and ranking.
//!
//! These find problems that have no CVE number because they are settings, not software bugs:
//! services left without a password, cleartext logins, management interfaces on the network.
//!
//! Every check is non-destructive: it only reads what the service sends to anyone who
//! connects, or tries the documented anonymous access (FTP `anonymous`, MQTT without
//! credentials). Nothing is written, changed or exploited. See detect.rs for each probe.

/// One built-in check.
#[derive(Debug)]
pub struct Check {
    pub id: &'static str,
    pub title: &'static str,
    /// CVSS v4.0 base score (Proton computed it from the vector in the comment above each check).
    pub score: f64,
    pub solution: &'static str,
}

// CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N
pub static TELNET: Check = Check {
    id: "PIS-0001",
    title: "Telnet service enabled (cleartext remote login)",
    score: 6.0,
    solution: "Disable Telnet and use SSH instead. If the device cannot run SSH, block port 23 on the network and \
               change any default password.",
};

// CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N
pub static FTP_ANONYMOUS: Check = Check {
    id: "PIS-0002",
    title: "Anonymous FTP login allowed",
    score: 6.9,
    solution: "Disable anonymous access in the FTP server settings (vsftpd: anonymous_enable=NO), or remove the \
               FTP service if it is not needed.",
};

// CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
pub static REDIS_NOAUTH: Check = Check {
    id: "PIS-0003",
    title: "Redis database accessible without authentication",
    score: 9.3,
    solution: "Set a password (requirepass / ACL users), bind Redis to 127.0.0.1 unless remote access is needed, \
               and enable protected-mode.",
};

// CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
pub static VNC_NOAUTH: Check = Check {
    id: "PIS-0004",
    title: "VNC remote desktop without password",
    score: 9.3,
    solution: "Configure a VNC password (or system authentication), and allow VNC only through SSH or a VPN.",
};

// CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
pub static DOCKER_API: Check = Check {
    id: "PIS-0005",
    title: "Docker Engine API exposed without authentication",
    score: 10.0,
    solution: "Stop exposing the Docker socket over TCP (remove -H tcp://… / \"hosts\" in daemon.json), or protect \
               it with TLS client certificates (port 2376).",
};

// CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N
pub static ELASTIC_NOAUTH: Check = Check {
    id: "PIS-0006",
    title: "Elasticsearch accessible without authentication",
    score: 9.3,
    solution: "Enable Elasticsearch security (xpack.security.enabled: true) with passwords and TLS, and bind it to \
               a private interface.",
};

// CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N
pub static MEMCACHED_NOAUTH: Check = Check {
    id: "PIS-0007",
    title: "Memcached accessible without authentication",
    score: 6.9,
    solution: "Bind memcached to 127.0.0.1 (-l 127.0.0.1), disable UDP (-U 0) and enable SASL if remote access is \
               required.",
};

// CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N
pub static MQTT_ANONYMOUS: Check = Check {
    id: "PIS-0008",
    title: "MQTT broker allows anonymous clients",
    score: 6.9,
    solution: "Disable anonymous access (Mosquitto: allow_anonymous false), add a password file and use TLS \
               (port 8883).",
};

// CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
pub static HTTP_CLEARTEXT_LOGIN: Check = Check {
    id: "PIS-0009",
    title: "Login page served over unencrypted HTTP",
    score: 5.9,
    solution: "Enable HTTPS on the device and redirect HTTP to HTTPS. If that is not possible, only manage the \
               device from a trusted, wired network.",
};

// CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N
pub static RDP_EXPOSED: Check = Check {
    id: "PIS-0010",
    title: "Remote Desktop (RDP) reachable",
    score: 0.0,
    solution: "Allow RDP only from trusted addresses, require Network Level Authentication, keep Windows updated, \
               and never forward port 3389 from the internet.",
};

// CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N
pub static SMB_EXPOSED: Check = Check {
    id: "PIS-0011",
    title: "Windows file sharing (SMB) reachable",
    score: 0.0,
    solution: "Keep the device updated, disable SMBv1, and make sure port 445 is not forwarded by the router.",
};

// CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N
pub static VERSION_DISCLOSED: Check = Check {
    id: "PIS-0012",
    title: "Software version detected",
    score: 0.0,
    solution: "Keep the software updated. Many servers can hide the version (Apache: ServerTokens Prod; nginx: \
               server_tokens off).",
};

// CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N
pub static FTP_CLEARTEXT: Check = Check {
    id: "PIS-0013",
    title: "Unencrypted FTP service",
    score: 2.1,
    solution: "Use SFTP (over SSH) or FTPS instead, or disable the FTP service.",
};

// CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N
pub static DATABASE_EXPOSED: Check = Check {
    id: "PIS-0014",
    title: "Database server reachable from the network",
    score: 0.0,
    solution: "Bind the database to 127.0.0.1 or a private interface, and allow remote users only from the hosts \
               that need them.",
};

/// A check that matched, with what proved it.
#[derive(Clone, Debug)]
pub struct Finding {
    pub check: &'static Check,
    pub port: u16,
    pub evidence: String,
}

impl Check {
    pub fn finding(&'static self, port: u16, evidence: impl Into<String>) -> Finding {
        Finding { check: self, port, evidence: evidence.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_are_consistent() {
        let all = [
            &TELNET,
            &FTP_ANONYMOUS,
            &REDIS_NOAUTH,
            &VNC_NOAUTH,
            &DOCKER_API,
            &ELASTIC_NOAUTH,
            &MEMCACHED_NOAUTH,
            &MQTT_ANONYMOUS,
            &HTTP_CLEARTEXT_LOGIN,
            &RDP_EXPOSED,
            &SMB_EXPOSED,
            &VERSION_DISCLOSED,
            &FTP_CLEARTEXT,
            &DATABASE_EXPOSED,
        ];
        let mut ids = std::collections::HashSet::new();
        for (i, c) in all.iter().enumerate() {
            assert!(ids.insert(c.id), "duplicate id {}", c.id);
            assert_eq!(c.id, format!("PIS-{:04}", i + 1));
            assert!((0.0..=10.0).contains(&c.score));
            assert!(c.title.len() <= 200 && c.solution.len() <= 1000);
        }
    }
}
