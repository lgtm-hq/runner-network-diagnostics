"use strict";
const DIRECTORY = "/etc/systemd/resolved.conf.d";
const FILENAME = "99-lgtm-agent-dns.conf";
const MAIN = "/etc/systemd/resolved.conf";
const PLATFORM = `${DIRECTORY}/90-egress-proxy.conf`;
const TARGET = `${DIRECTORY}/${FILENAME}`;
const LIMIT = 256 * 1024;
module.exports = { DIRECTORY, FILENAME, MAIN, PLATFORM, TARGET, LIMIT };
