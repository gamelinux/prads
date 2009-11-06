DROP DATABASE prads;

CREATE DATABASE prads;

use prads;

CREATE TABLE IF NOT EXISTS `asset` (
   `assetID`        INT UNSIGNED NOT NULL AUTO_INCREMENT,
   `hostname`       VARCHAR(255) NOT NULL default '',
   `sensorID`       INT UNSIGNED NOT NULL default '0',
   `timestamp`      DATETIME NOT NULL default '0000-00-00 00:00:00',
   `ipaddress`      decimal(39,0) unsigned default NULL,
   `service`        VARCHAR(50) NOT NULL default '',
   `application`    VARCHAR(255) NOT NULL default '',
   `port`           INT UNSIGNED NOT NULL default '0',
   `protocol`       TINYINT UNSIGNED NOT NULL default '0',
   `application`    VARCHAR(255) NOT NULL default '',
   `hex_payload`    VARCHAR(255) default '',
   UNIQUE           KEY `unique_row_key` (`ipaddress`,`port`,`protocol`,`service`,`application`),
   PRIMARY          KEY (`sensorID`,`assetID`)
) TYPE=InnoDB;

CREATE TABLE IF NOT EXISTS `protocol` (
  `protoID`         TINYINT UNSIGNED NOT NULL default '',
  `name`            VARCHAR(100) NOT NULL default '',
  PRIMARY           KEY (`protoID`)
) TYPE=InnoDB;

INSERT INTO protocol VALUES (0,   'HOPOPT');
INSERT INTO protocol VALUES (1,   'ICMP');
INSERT INTO protocol VALUES (2,   'IGMP');
INSERT INTO protocol VALUES (3,   'GGP');
INSERT INTO protocol VALUES (4,   'IP');
INSERT INTO protocol VALUES (5,   'ST');
INSERT INTO protocol VALUES (6,   'TCP');
INSERT INTO protocol VALUES (7,   'CBT');
INSERT INTO protocol VALUES (8,   'EGP');
INSERT INTO protocol VALUES (9,   'IGP');
INSERT INTO protocol VALUES (10,  'BBN-RCC-MON');
INSERT INTO protocol VALUES (11,  'NVP-II');
INSERT INTO protocol VALUES (12,  'PUP');
INSERT INTO protocol VALUES (13,  'ARGUS');
INSERT INTO protocol VALUES (14,  'EMCON');
INSERT INTO protocol VALUES (15,  'XNET');
INSERT INTO protocol VALUES (16,  'CHAOS');
INSERT INTO protocol VALUES (17,  'UDP');
INSERT INTO protocol VALUES (18,  'MUX');
INSERT INTO protocol VALUES (19,  'DCN-MEAS');

INSERT INTO protocol VALUES (20,  'HMP');
INSERT INTO protocol VALUES (21,  'PRM');
INSERT INTO protocol VALUES (22,  'XNS-IDP');
INSERT INTO protocol VALUES (23,  'TRUNK-1');
INSERT INTO protocol VALUES (24,  'TRUNK-2');
INSERT INTO protocol VALUES (25,  'LEAF-1');
INSERT INTO protocol VALUES (26,  'LEAF-2');
INSERT INTO protocol VALUES (27,  'RDP');
INSERT INTO protocol VALUES (28,  'IRTP');
INSERT INTO protocol VALUES (29,  'ISO-TP4');

INSERT INTO protocol VALUES (30,  'NETBLT');
INSERT INTO protocol VALUES (31,  'MFE-NSP');
INSERT INTO protocol VALUES (32,  'MERIT-INP');
INSERT INTO protocol VALUES (33,  'DCCP');
INSERT INTO protocol VALUES (34,  '3PC');
INSERT INTO protocol VALUES (35,  'IDPR');
INSERT INTO protocol VALUES (36,  'XTP');
INSERT INTO protocol VALUES (37,  'DDP');
INSERT INTO protocol VALUES (38,  'IDPR-CMTP');
INSERT INTO protocol VALUES (39,  'TP++');

INSERT INTO protocol VALUES (40,  'IL');
INSERT INTO protocol VALUES (41,  'IPv6');
INSERT INTO protocol VALUES (42,  'SDRP');
INSERT INTO protocol VALUES (43,  'IPv6-Route');
INSERT INTO protocol VALUES (44,  'IPv6-Frag');
INSERT INTO protocol VALUES (45,  'IDRP');
INSERT INTO protocol VALUES (46,  'RSVP');
INSERT INTO protocol VALUES (47,  'GRE');
INSERT INTO protocol VALUES (48,  'MHRP');
INSERT INTO protocol VALUES (49,  'BNA');

INSERT INTO protocol VALUES (50,  'ESP');
INSERT INTO protocol VALUES (51,  'AH');
INSERT INTO protocol VALUES (52,  'I-NLSP');
INSERT INTO protocol VALUES (53,  'SWIPE');
INSERT INTO protocol VALUES (54,  'NARP');
INSERT INTO protocol VALUES (55,  'MOBILE');
INSERT INTO protocol VALUES (56,  'TLSP');
INSERT INTO protocol VALUES (57,  'SKIP');
INSERT INTO protocol VALUES (58,  'IPv6-ICMP');
INSERT INTO protocol VALUES (59,  'IPv6-NoNxt');

INSERT INTO protocol VALUES (60,  'IPv6-Opts');
INSERT INTO protocol VALUES (61,  'Any host internal protocol');
INSERT INTO protocol VALUES (62,  'CFTP');
INSERT INTO protocol VALUES (63,  'Any local network');
INSERT INTO protocol VALUES (64,  'SAT-EXPAK');
INSERT INTO protocol VALUES (65,  'KRYPTOLAN');
INSERT INTO protocol VALUES (66,  'RVD');
INSERT INTO protocol VALUES (67,  'IPPC');
INSERT INTO protocol VALUES (68,  'Any distributed file system');
INSERT INTO protocol VALUES (69,  'SAT-MON');

INSERT INTO protocol VALUES (70,  'VISA');
INSERT INTO protocol VALUES (71,  'IPCV');
INSERT INTO protocol VALUES (72,  'CPNX');
INSERT INTO protocol VALUES (73,  'CPHB');
INSERT INTO protocol VALUES (74,  'WSN');
INSERT INTO protocol VALUES (75,  'PVP');
INSERT INTO protocol VALUES (76,  'BR-SAT-MON');
INSERT INTO protocol VALUES (77,  'SUN-ND');
INSERT INTO protocol VALUES (78,  'WB-MON');
INSERT INTO protocol VALUES (79,  'WB-EXPAK');

INSERT INTO protocol VALUES (80,  'ISO-IP');
INSERT INTO protocol VALUES (81,  'VMTP');
INSERT INTO protocol VALUES (82,  'SECURE-VMTP');
INSERT INTO protocol VALUES (83,  'VINES');
INSERT INTO protocol VALUES (84,  'TTP');
INSERT INTO protocol VALUES (85,  'NSFNET-IGP');
INSERT INTO protocol VALUES (86,  'DGP');
INSERT INTO protocol VALUES (87,  'TCF');
INSERT INTO protocol VALUES (88,  'EIGRP');
INSERT INTO protocol VALUES (89,  'OSPF');

INSERT INTO protocol VALUES (90,  'Sprite-RPC');
INSERT INTO protocol VALUES (91,  'LARP');
INSERT INTO protocol VALUES (92,  'MTP');
INSERT INTO protocol VALUES (93,  'AX.25');
INSERT INTO protocol VALUES (94,  'IPIP');
INSERT INTO protocol VALUES (95,  'MICP');
INSERT INTO protocol VALUES (96,  'SCC-SP');
INSERT INTO protocol VALUES (97,  'ETHERIP');
INSERT INTO protocol VALUES (98,  'ENCAP');
INSERT INTO protocol VALUES (99,  'Any private encryption scheme');

INSERT INTO protocol VALUES (100,  'GMTP');
INSERT INTO protocol VALUES (101,  'IFMP');
INSERT INTO protocol VALUES (102,  'PNNI');
INSERT INTO protocol VALUES (103,  'PIM');
INSERT INTO protocol VALUES (104,  'ARIS');
INSERT INTO protocol VALUES (105,  'SCPS');
INSERT INTO protocol VALUES (106,  'QNX');
INSERT INTO protocol VALUES (107,  'A/N');
INSERT INTO protocol VALUES (108,  'IPComp');
INSERT INTO protocol VALUES (109,  'SNP');

INSERT INTO protocol VALUES (110,  'Compaq-Peer');
INSERT INTO protocol VALUES (111,  'IPX-in-IP');
INSERT INTO protocol VALUES (112,  'VRRP');
INSERT INTO protocol VALUES (113,  'PGM');
INSERT INTO protocol VALUES (114,  'Any 0-hop protocol');
INSERT INTO protocol VALUES (115,  'L2TP');
INSERT INTO protocol VALUES (116,  'DDX');
INSERT INTO protocol VALUES (117,  'IATP');
INSERT INTO protocol VALUES (118,  'STP');
INSERT INTO protocol VALUES (119,  'SRP');

INSERT INTO protocol VALUES (120,  'UTI');
INSERT INTO protocol VALUES (121,  'SMP');
INSERT INTO protocol VALUES (122,  'SM');
INSERT INTO protocol VALUES (123,  'PTP');
INSERT INTO protocol VALUES (124,  'IS-IS over IPv4');
INSERT INTO protocol VALUES (125,  'FIRE');
INSERT INTO protocol VALUES (126,  'CRTP');
INSERT INTO protocol VALUES (127,  'CRUDP');
INSERT INTO protocol VALUES (128,  'SSCOPMCE');
INSERT INTO protocol VALUES (129,  'IPLT');

INSERT INTO protocol VALUES (130,  'SPS');
INSERT INTO protocol VALUES (131,  'PIPE');
INSERT INTO protocol VALUES (132,  'SCTP');
INSERT INTO protocol VALUES (133,  'FC');
INSERT INTO protocol VALUES (134,  'RSVP-E2E-IGNORE');
INSERT INTO protocol VALUES (135,  'Mobility Header');
INSERT INTO protocol VALUES (136,  'UDP Lite');
INSERT INTO protocol VALUES (137,  'MPLS-in-IP');
INSERT INTO protocol VALUES (138,  'MANET');
INSERT INTO protocol VALUES (139,  'HIP');

INSERT INTO protocol VALUES (140,  'Shim6');

INSERT INTO protocol VALUES (141,  'UNASSIGNED');
INSERT INTO protocol VALUES (142,  'UNASSIGNED');
INSERT INTO protocol VALUES (143,  'UNASSIGNED');
INSERT INTO protocol VALUES (144,  'UNASSIGNED');
INSERT INTO protocol VALUES (145,  'UNASSIGNED');
INSERT INTO protocol VALUES (146,  'UNASSIGNED');
INSERT INTO protocol VALUES (147,  'UNASSIGNED');
INSERT INTO protocol VALUES (148,  'UNASSIGNED');
INSERT INTO protocol VALUES (149,  'UNASSIGNED');

INSERT INTO protocol VALUES (150,  'UNASSIGNED');
INSERT INTO protocol VALUES (151,  'UNASSIGNED');
INSERT INTO protocol VALUES (152,  'UNASSIGNED');
INSERT INTO protocol VALUES (153,  'UNASSIGNED');
INSERT INTO protocol VALUES (154,  'UNASSIGNED');
INSERT INTO protocol VALUES (155,  'UNASSIGNED');
INSERT INTO protocol VALUES (156,  'UNASSIGNED');
INSERT INTO protocol VALUES (157,  'UNASSIGNED');
INSERT INTO protocol VALUES (158,  'UNASSIGNED');
INSERT INTO protocol VALUES (159,  'UNASSIGNED');
#... upto 254

# INSERT INTO protocol VALUES (254,  'UNASSIGNED');

INSERT INTO protocol VALUES (255,  'Reserved');



