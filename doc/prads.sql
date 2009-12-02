DROP DATABASE IF EXISTS prads;
CREATE DATABASE prads;

-- use prads; -- mysql specific
drop table if exists asset;
-- autoincrements in postgres
drop sequence asset_id_seq;
create sequence asset_id_seq;

CREATE TABLE asset (
   -- assetID        INT NOT NULL AUTO_INCREMENT,
   assetID        INT NOT NULL default nextval('asset_id_seq'),
   hostname       TEXT default '',
   sensorID       INT NOT NULL default '0',
   timestamp      TIMESTAMP default NULL,
   --ipaddress      decimal(39,0) default NULL,
   ipaddress      inet default null,
   mac_address    VARCHAR(20) NOT NULL default '',
   mac_vendor     VARCHAR(50) NOT NULL default '',
   os             TEXT default '',
   os_details     TEXT default '',
   os_fingerprint TEXT default '',
   link           TEXT default '',
   distance       INT default '0',
   service        TEXT default '',
   application    TEXT default '',
   port           INT default '0',
   protocol       SMALLINT NOT NULL default '0',
   hex_payload    TEXT default '',
   --constraint uniq unique (ipaddress,port,protocol,service,application),
   --UNIQUE           KEY unique_row_key (ipaddress,port,protocol,service,application),
   --PRIMARY          KEY (sensorID,assetID),
   constraint prikey primary key (sensorID, assetID),
   CHECK (assetID>=0),
   CHECK (sensorID>=0),
   CHECK (distance>=0),
   CHECK (port>=0),
   CHECK (protocol >=0)
);

/* mysql
CREATE TABLE IF NOT EXISTS `asset` (
   `assetID`        INT UNSIGNED NOT NULL AUTO_INCREMENT,
   `hostname`       VARCHAR(255) NOT NULL default '',
   `sensorID`       INT UNSIGNED NOT NULL default '0',
   `timestamp`      DATETIME NOT NULL default '0000-00-00 00:00:00',
   `ipaddress`      decimal(39,0) unsigned default NULL,
   `mac_address`    VARCHAR(20) NOT NULL default '',
   `mac_vendor`     VARCHAR(50) NOT NULL default '',
   `os`             VARCHAR(20) NOT NULL default '',
   `os_details`     VARCHAR(255) NOT NULL default '',
   `os_fingerprint` VARCHAR(255) NOT NULL default '',
   `link`           VARCHAR(20) NOT NULL default '',
   `distance`       INT UNSIGNED NOT NULL default '0',
   `service`        VARCHAR(50) NOT NULL default '',
   `application`    VARCHAR(255) NOT NULL default '',
   `port`           INT UNSIGNED NOT NULL default '0',
   `protocol`       TINYINT UNSIGNED NOT NULL default '0',
   `hex_payload`    VARCHAR(255) default '',
   UNIQUE           KEY `unique_row_key` (`ipaddress`,`port`,`protocol`,`service`,`application`),
   PRIMARY          KEY (`sensorID`,`assetID`)
) TYPE=InnoDB;

-- INET_ATON6
-- DELIMITER //
CREATE FUNCTION INET_ATON6(n CHAR(39))
RETURNS DECIMAL(39)
BEGIN
    RETURN CAST(CONV(SUBSTRING(n FROM  1 FOR 4), 16, 10) AS DECIMAL(39))
                       * 5192296858534827628530496329220096 -- 65536 ^ 7
         + CAST(CONV(SUBSTRING(n FROM  6 FOR 4), 16, 10) AS DECIMAL(39))
                       *      79228162514264337593543950336 -- 65536 ^ 6
         + CAST(CONV(SUBSTRING(n FROM 11 FOR 4), 16, 10) AS DECIMAL(39))
                       *          1208925819614629174706176 -- 65536 ^ 5
         + CAST(CONV(SUBSTRING(n FROM 16 FOR 4), 16, 10) AS DECIMAL(39)) 
                       *               18446744073709551616 -- 65536 ^ 4
         + CAST(CONV(SUBSTRING(n FROM 21 FOR 4), 16, 10) AS DECIMAL(39))
                       *                    281474976710656 -- 65536 ^ 3
         + CAST(CONV(SUBSTRING(n FROM 26 FOR 4), 16, 10) AS DECIMAL(39))
                       *                         4294967296 -- 65536 ^ 2
         + CAST(CONV(SUBSTRING(n FROM 31 FOR 4), 16, 10) AS DECIMAL(39))
                       *                              65536 -- 65536 ^ 1
         + CAST(CONV(SUBSTRING(n FROM 36 FOR 4), 16, 10) AS DECIMAL(39))
         ;
END;
DELIMITER ;
-- INET_NTOA6

DELIMITER //
CREATE FUNCTION INET_NTOA6(n DECIMAL(39) UNSIGNED)
RETURNS CHAR(39)
DETERMINISTIC
BEGIN
  DECLARE a CHAR(39)             DEFAULT '';
  DECLARE i INT                  DEFAULT 7;
  DECLARE q DECIMAL(39)          DEFAULT 0;
  DECLARE r INT                  DEFAULT 0;
  WHILE i DO
    -- DIV doesn't work with nubers > bigint
    SET q := FLOOR(n / 65536);
    SET r := n MOD 65536;
    SET n := q;
    SET a := CONCAT_WS(':', LPAD(CONV(r, 10, 16), 4, '0'), a);

    SET i := i - 1;
  END WHILE;

  SET a := TRIM(TRAILING ':' FROM CONCAT_WS(':',
                                            LPAD(CONV(n, 10, 16), 4, '0'),
                                            a));

  RETURN a;

END;
//
DELIMITER ;
*/




-- sqlight
/* CREATE TABLE asset (
  ip TEXT,
  service TEXT,
  time TEXT,
  fingerprint TEXT,
  mac TEXT,
  os TEXT,
  details TEXT,
  link TEXT,
  distance TEXT,
  reporting TEXT
)
*/

drop table protocol;
CREATE TABLE protocol (
  protoID         SMALLINT,
  name            VARCHAR(100) NOT NULL default '',
  PRIMARY           KEY (protoID),
  CHECK(protoID >= 0)
);

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
--#... upto 254

--# INSERT INTO protocol VALUES (254,  'UNASSIGNED');

INSERT INTO protocol VALUES (255,  'Reserved');

