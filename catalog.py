"""Static catalog: intelligence sources (with Admiralty reliability) and well-known threat actors.

Admiralty / NATO source-reliability scale used in real CTI work:
  A completely reliable, B usually reliable, C fairly reliable,
  D not usually reliable, E unreliable, F reliability cannot be judged.
"""

RELIABILITY_WEIGHT = {"A": 0.95, "B": 0.80, "C": 0.60, "D": 0.40, "E": 0.20, "F": 0.50}
RELIABILITY_TEXT = {
    "A": "Completely reliable", "B": "Usually reliable", "C": "Fairly reliable",
    "D": "Not usually reliable", "E": "Unreliable", "F": "Cannot be judged",
}

GH = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/"

# ---------------------------------------------------------------- news / report sources
# ctidigest.com aggregates public security RSS feeds (BleepingComputer, Krebs, The Hacker News,
# Microsoft Security Blog, ...). We rebuild the same kind of feed list here.
NEWS_SOURCES = [
    ("bleepingcomputer", "BleepingComputer", "https://www.bleepingcomputer.com/", "https://www.bleepingcomputer.com/feed/", "B"),
    ("thehackernews", "The Hacker News", "https://thehackernews.com/", "https://feeds.feedburner.com/TheHackersNews", "B"),
    ("krebsonsecurity", "Krebs on Security", "https://krebsonsecurity.com/", "https://krebsonsecurity.com/feed/", "B"),
    ("microsoft-security", "Microsoft Security Blog", "https://www.microsoft.com/en-us/security/blog/", "https://www.microsoft.com/en-us/security/blog/feed/", "A"),
    ("cisa-advisories", "CISA Advisories", "https://www.cisa.gov/news-events/cybersecurity-advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "A"),
    ("securityweek", "SecurityWeek", "https://www.securityweek.com/", "https://www.securityweek.com/feed/", "B"),
    ("darkreading", "Dark Reading", "https://www.darkreading.com/", "https://www.darkreading.com/rss.xml", "B"),
    ("therecord", "The Record", "https://therecord.media/", "https://therecord.media/feed/", "B"),
    ("talos", "Cisco Talos", "https://blog.talosintelligence.com/", "https://blog.talosintelligence.com/rss/", "A"),
    ("unit42", "Palo Alto Unit 42", "https://unit42.paloaltonetworks.com/", "https://unit42.paloaltonetworks.com/feed/", "A"),
    ("sans-isc", "SANS Internet Storm Center", "https://isc.sans.edu/", "https://isc.sans.edu/rssfeed_full.xml", "A"),
    ("securelist", "Kaspersky Securelist", "https://securelist.com/", "https://securelist.com/feed/", "A"),
    ("welivesecurity", "ESET WeLiveSecurity", "https://www.welivesecurity.com/", "https://www.welivesecurity.com/en/rss/feed/", "A"),
    ("sophos", "Sophos News", "https://news.sophos.com/", "https://news.sophos.com/en-us/feed/", "A"),
    ("checkpoint-research", "Check Point Research", "https://research.checkpoint.com/", "https://research.checkpoint.com/feed/", "A"),
    ("sentinelone-labs", "SentinelLabs", "https://www.sentinelone.com/labs/", "https://www.sentinelone.com/labs/feed/", "A"),
    ("dfir-report", "The DFIR Report", "https://thedfirreport.com/", "https://thedfirreport.com/feed/", "A"),
    ("project-zero", "Google Project Zero", "https://googleprojectzero.blogspot.com/", "https://googleprojectzero.blogspot.com/feeds/posts/default", "A"),
    ("google-threat-intel", "Google Threat Intelligence", "https://cloud.google.com/blog/topics/threat-intelligence", "https://cloud.google.com/blog/topics/threat-intelligence/rss/", "A"),
    ("ncsc-uk", "UK NCSC", "https://www.ncsc.gov.uk/", "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", "A"),
    ("helpnetsecurity", "Help Net Security", "https://www.helpnetsecurity.com/", "https://www.helpnetsecurity.com/feed/", "B"),
    ("infosecurity-magazine", "Infosecurity Magazine", "https://www.infosecurity-magazine.com/", "https://www.infosecurity-magazine.com/rss/news/", "B"),
    ("cyberscoop", "CyberScoop", "https://cyberscoop.com/", "https://cyberscoop.com/feed/", "B"),
    ("malwarebytes", "Malwarebytes Labs", "https://www.malwarebytes.com/blog", "https://www.malwarebytes.com/blog/feed/index.xml", "B"),
    ("recorded-future", "Recorded Future", "https://www.recordedfuture.com/", "https://www.recordedfuture.com/feed", "B"),
    ("schneier", "Schneier on Security", "https://www.schneier.com/", "https://www.schneier.com/feed/atom/", "B"),
    ("troyhunt", "Troy Hunt", "https://www.troyhunt.com/", "https://www.troyhunt.com/rss/", "B"),
    ("securityaffairs", "Security Affairs", "https://securityaffairs.com/", "https://securityaffairs.com/feed", "C"),
    ("grahamcluley", "Graham Cluley", "https://grahamcluley.com/", "https://grahamcluley.com/feed/", "C"),
    ("hackread", "Hackread", "https://hackread.com/", "https://hackread.com/feed/", "C"),
]

# ---------------------------------------------------------------- IOC feeds (no API key needed)
# (id, name, homepage, url, reliability, format, points, tag, description)
IOC_FEEDS = [
    ("ipsum", "IPsum (30+ blacklists)", "https://github.com/stamparm/ipsum",
     "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt", "B", "ipsum", 0, "blacklisted",
     "Daily aggregate of 30+ public IP blacklists; the number = how many lists contain the IP"),
    ("feodo", "abuse.ch Feodo Tracker (botnet C2)", "https://feodotracker.abuse.ch/", GH + "feodo.ipset", "A", "ipset", 60, "botnet-c2",
     "Active botnet command-and-control servers (Dridex, Emotet, QakBot family)"),
    ("spamhaus_drop", "Spamhaus DROP", "https://www.spamhaus.org/drop/", GH + "spamhaus_drop.netset", "A", "netset", 55, "hijacked-netblock",
     "Hijacked or criminal-operated netblocks - Spamhaus says drop all traffic"),
    ("firehol_level1", "FireHOL Level 1", "https://iplists.firehol.org/", GH + "firehol_level1.netset", "A", "netset", 40, "attacks",
     "Curated, low false-positive blocklist of networks that attack or abuse"),
    ("et_compromised", "Emerging Threats compromised hosts", "https://rules.emergingthreats.net/", GH + "et_compromised.ipset", "B", "ipset", 30, "compromised",
     "Hosts Proofpoint Emerging Threats sees as compromised"),
    ("dshield", "DShield top attackers", "https://www.dshield.org/", GH + "dshield.netset", "B", "netset", 30, "scanner",
     "SANS DShield: top attacking subnets of the last days"),
    ("blocklist_de", "blocklist.de attackers", "https://www.blocklist.de/", GH + "blocklist_de.ipset", "C", "ipset", 25, "brute-force",
     "IPs reported for SSH, mail, FTP, web brute-force and abuse in the last 48 h"),
    ("greensnow", "GreenSnow", "https://greensnow.co/", GH + "greensnow.ipset", "C", "ipset", 20, "brute-force",
     "IPs seen brute-forcing or scanning GreenSnow sensors"),
    ("bruteforceblocker", "BruteForceBlocker", "https://danger.rulez.sk/", GH + "bruteforceblocker.ipset", "C", "ipset", 20, "ssh-brute-force",
     "SSH brute-force sources"),
    ("tor_exits", "Tor exit nodes", "https://www.torproject.org/", GH + "tor_exits.ipset", "A", "ipset", 15, "tor-exit",
     "Tor exit relays - anonymised traffic, not malicious by itself"),
    ("threatfox", "abuse.ch ThreatFox", "https://threatfox.abuse.ch/",
     "https://threatfox.abuse.ch/export/json/recent/", "A", "threatfox", 50, "malware-ioc",
     "Recent malware IOCs (C2 IPs, domains, URLs, hashes) shared by the community"),
    ("urlhaus", "abuse.ch URLhaus", "https://urlhaus.abuse.ch/",
     "https://urlhaus.abuse.ch/downloads/csv_recent/", "A", "urlhaus", 50, "malware-url",
     "Recent URLs distributing malware"),
]

OTHER_SOURCES = [
    ("ctidigest", "OpenSource CTI Digest", "aggregator", "https://ctidigest.com/", "https://ctidigest.com/", "B",
     "The assignment's reference platform: news feed + sources + IOC database"),
    ("cisa-kev", "CISA Known Exploited Vulnerabilities", "vulnerability-catalog",
     "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
     "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "A",
     "Vulnerabilities confirmed as exploited in the wild"),
    ("annual-security-reports", "Awesome Annual Security Reports", "annual-reports",
     "https://github.com/jacobdjwilson/awesome-annual-security-reports",
     "https://raw.githubusercontent.com/jacobdjwilson/awesome-annual-security-reports/main/README.md", "B",
     "Curated list of annual security reports (Lab 7.2 dataset)"),
    ("analyst-lookups", "This platform (analyst lookups)", "derived", "", "", "C",
     "IPs this platform itself judged malicious during a lookup"),
    ("sample-data", "Offline sample data", "sample", "", "", "F",
     "Built-in demo records used only when the internet is unavailable"),
]

# ---------------------------------------------------------------- threat actors
# (id, name, type, origin, motivation, aliases)
THREAT_ACTORS = [
    ("apt28", "APT28", "nation-state", "Russia", "espionage", ["Fancy Bear", "Sofacy", "Forest Blizzard", "Strontium", "Sednit"]),
    ("apt29", "APT29", "nation-state", "Russia", "espionage", ["Cozy Bear", "Midnight Blizzard", "Nobelium", "The Dukes"]),
    ("sandworm", "Sandworm", "nation-state", "Russia", "sabotage", ["APT44", "Seashell Blizzard", "Voodoo Bear", "Iridium"]),
    ("turla", "Turla", "nation-state", "Russia", "espionage", ["Secret Blizzard", "Snake", "Venomous Bear", "Uroburos"]),
    ("gamaredon", "Gamaredon", "nation-state", "Russia", "espionage", ["Aqua Blizzard", "Primitive Bear", "Shuckworm"]),
    ("star-blizzard", "Star Blizzard", "nation-state", "Russia", "espionage", ["Callisto", "ColdRiver", "Seaborgium"]),
    ("lazarus", "Lazarus Group", "nation-state", "North Korea", "financial / espionage", ["Hidden Cobra", "Diamond Sleet", "Zinc", "Labyrinth Chollima"]),
    ("kimsuky", "Kimsuky", "nation-state", "North Korea", "espionage", ["Emerald Sleet", "Velvet Chollima", "Thallium", "APT43"]),
    ("andariel", "Andariel", "nation-state", "North Korea", "financial / espionage", ["Onyx Sleet", "Silent Chollima", "Stonefly"]),
    ("scarcruft", "ScarCruft", "nation-state", "North Korea", "espionage", ["APT37", "Reaper", "Ricochet Chollima"]),
    ("volt-typhoon", "Volt Typhoon", "nation-state", "China", "pre-positioning", ["Vanguard Panda", "Bronze Silhouette", "Insidious Taurus"]),
    ("salt-typhoon", "Salt Typhoon", "nation-state", "China", "espionage", ["Earth Estries", "GhostEmperor", "UNC2286"]),
    ("flax-typhoon", "Flax Typhoon", "nation-state", "China", "espionage", ["Ethereal Panda"]),
    ("silk-typhoon", "Silk Typhoon", "nation-state", "China", "espionage", ["Hafnium"]),
    ("apt41", "APT41", "nation-state", "China", "espionage / financial", ["Winnti", "Brass Typhoon", "Wicked Panda", "Barium"]),
    ("mustang-panda", "Mustang Panda", "nation-state", "China", "espionage", ["Bronze President", "TA416", "Earth Preta", "RedDelta"]),
    ("apt40", "APT40", "nation-state", "China", "espionage", ["Gingham Typhoon", "Leviathan", "Kryptonite Panda"]),
    ("muddywater", "MuddyWater", "nation-state", "Iran", "espionage", ["Mango Sandstorm", "Static Kitten", "Seedworm", "Mercury"]),
    ("apt33", "APT33", "nation-state", "Iran", "espionage / sabotage", ["Peach Sandstorm", "Elfin", "Refined Kitten", "Holmium"]),
    ("apt35", "APT35", "nation-state", "Iran", "espionage", ["Charming Kitten", "Mint Sandstorm", "Phosphorus", "APT42"]),
    ("oilrig", "OilRig", "nation-state", "Iran", "espionage", ["APT34", "Hazel Sandstorm", "Helix Kitten"]),
    ("transparent-tribe", "Transparent Tribe", "nation-state", "Pakistan", "espionage", ["APT36", "Mythic Leopard"]),
    ("sidewinder", "SideWinder", "nation-state", "South Asia", "espionage", ["Rattlesnake", "T-APT-04"]),
    ("scattered-spider", "Scattered Spider", "cybercrime", "International", "financial", ["Octo Tempest", "UNC3944", "0ktapus", "Muddled Libra"]),
    ("fin7", "FIN7", "cybercrime", "Russia-linked", "financial", ["Carbon Spider", "Sangria Tempest", "ELBRUS"]),
    ("ta505", "TA505", "cybercrime", "Russia-linked", "financial", ["Lace Tempest", "FIN11"]),
    ("evil-corp", "Evil Corp", "cybercrime", "Russia", "financial", ["Indrik Spider", "Manatee Tempest"]),
    ("lapsus", "Lapsus$", "cybercrime", "International", "extortion", ["Strawberry Tempest", "DEV-0537"]),
    ("shinyhunters", "ShinyHunters", "cybercrime", "International", "data theft / extortion", ["UNC6040"]),
    ("lockbit", "LockBit", "ransomware", "Russia-linked", "financial", ["LockBit 3.0", "LockBit Black"]),
    ("alphv", "ALPHV", "ransomware", "Russia-linked", "financial", ["BlackCat", "Noberus"]),
    ("clop", "Cl0p", "ransomware", "Russia-linked", "financial", ["Clop"]),
    ("akira", "Akira", "ransomware", "Unknown", "financial", ["Akira ransomware"]),
    ("qilin", "Qilin", "ransomware", "Unknown", "financial", ["Agenda"]),
    ("black-basta", "Black Basta", "ransomware", "Russia-linked", "financial", ["BlackBasta"]),
    ("play", "Play", "ransomware", "Unknown", "financial", ["PlayCrypt", "Play ransomware"]),
    ("ransomhub", "RansomHub", "ransomware", "Unknown", "financial", ["Greenbottle"]),
    ("medusa", "Medusa", "ransomware", "Unknown", "financial", ["Medusa ransomware", "MedusaLocker"]),
    ("rhysida", "Rhysida", "ransomware", "Unknown", "financial", ["Rhysida ransomware"]),
    ("bianlian", "BianLian", "ransomware", "Unknown", "financial", ["BianLian ransomware"]),
    ("dragonforce", "DragonForce", "ransomware", "Unknown", "financial", ["DragonForce ransomware"]),
    ("safepay", "SafePay", "ransomware", "Unknown", "financial", ["SafePay ransomware"]),
    ("interlock", "Interlock", "ransomware", "Unknown", "financial", ["Interlock ransomware"]),
    ("inc-ransom", "INC Ransom", "ransomware", "Unknown", "financial", ["INC ransomware", "Lynx"]),
    ("hunters-international", "Hunters International", "ransomware", "Unknown", "financial", ["World Leaks"]),
]
