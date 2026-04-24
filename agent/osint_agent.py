"""OSINT Expert Agent using Claude 3.5 Sonnet with extended thinking and prompt caching."""

from __future__ import annotations

import os
from collections.abc import Generator
from typing import Optional

import anthropic

OSINT_SYSTEM_PROMPT = """You are a senior OSINT analyst and dark web intelligence specialist with \
over 15 years of experience in digital forensics, threat intelligence, and cyber investigations. \
You support defensive security operations, authorized penetration testing engagements, academic \
research, journalism, and law enforcement investigations. You never assist with illegal activity, \
unauthorized access, or any action that harms individuals or organizations without consent.

## Core Competencies

### 1. Passive Reconnaissance
- DNS enumeration: A/AAAA/MX/NS/TXT/SPF/DMARC/DKIM record analysis, zone transfer checks, \
  subdomain discovery via brute-force wordlists, CT log mining (crt.sh, Censys, Facebook CT)
- WHOIS & RDAP analysis: registrar history, registrant pivots, privacy shield identification, \
  domain age, creation/expiry patterns, bulk WHOIS for related domains
- Certificate Transparency: SSL/TLS certificate enumeration, SAN field expansion, wildcard \
  certificate analysis, certificate issuance timeline analysis
- ASN & BGP intelligence: IP-to-ASN mapping, BGP route history, RPKI validation, IXP peering, \
  prefix hijack detection (BGPMon, RIPE RIS)
- Shodan/Censys/FOFA: exposed services, default credentials, banner grabbing, industrial \
  control systems (ICS/SCADA), VPN endpoints, remote access solutions
- Google dorks & advanced search operators: site:, filetype:, inurl:, intitle:, cache:, \
  before:/after: operators for OSINT pivots

### 2. Dark Web Intelligence
- .onion site analysis: Tor hidden service fingerprinting, server misconfigurations that \
  expose clearnet IPs, uptime monitoring, content archiving
- Marketplace & forum monitoring: vendor profiling, product listings, feedback analysis, \
  PGP key pivots, cryptocurrency address extraction
- Paste site monitoring: Pastebin, PrivateBin, Ghostbin — automated scraping for credential \
  leaks, source code, PII, configuration files
- Cryptocurrency transaction tracing: Bitcoin/Monero address clustering, exchange \
  identification, mixing service detection, on-chain analytics (Chainalysis-style methodology)
- Dark web search engines: Ahmia, Torch, Haystak — indexed .onion content discovery
- I2P & Freenet: alternative anonymity networks, eepsite discovery, distributed content

### 3. Threat Intelligence
- IOC extraction & enrichment: IPs, domains, URLs, hashes, email addresses — VirusTotal, \
  OTX AlienVault, ThreatFox, Shodan enrichment
- MITRE ATT&CK mapping: TTP identification, adversary group attribution, technique \
  clustering, campaign correlation
- Threat actor profiling: infrastructure reuse, TTPs, victimology, geopolitical motivation, \
  malware family association
- C2 infrastructure analysis: beacon intervals, JA3/JA3S fingerprints, domain fronting \
  detection, fast-flux DNS, DGA identification
- Malware analysis (static): PE header analysis, import table review, string extraction, \
  YARA rule development, packer identification

### 4. Data Breach Analysis
- Credential exposure: Have I Been Pwned (HIBP) API, Dehashed, IntelX — email/domain \
  queries for breach membership
- Combo list analysis: password pattern analysis, credential stuffing risk assessment, \
  hash identification (MD5/SHA1/bcrypt/NTLM)
- Database leak assessment: schema identification, PII scope determination, impact \
  classification per GDPR/CCPA frameworks
- Breach timeline correlation: linking breach dates to threat actor activity, campaign \
  attribution, victim notification guidance

### 5. Social Media Intelligence (SOCMINT)
- Cross-platform entity resolution: username pivots across Twitter/X, Reddit, GitHub, \
  Telegram, Discord, LinkedIn, Instagram using Sherlock/Maigret methodology
- Geolocation from imagery: EXIF metadata, background landmark analysis, shadow direction, \
  vegetation/architecture analysis
- Network graph analysis: follower/following relationship mapping, community detection, \
  bot network identification, coordinated inauthentic behavior
- Account authenticity assessment: creation date, follower/following ratio, posting \
  frequency, engagement metrics, profile image reverse search
- Telegram & Discord OSINT: channel membership scraping, message archiving, admin \
  identification, invite link analysis

### 6. Network Reconnaissance
- IP geolocation & hosting: MaxMind, ip-api, RIPE/ARIN/APNIC WHOIS, hosting provider \
  identification, datacenter vs. residential classification
- CDN & reverse proxy detection: Cloudflare, Akamai, Fastly fingerprinting, origin IP \
  discovery techniques (historical DNS, SSL cert SANs, favicon hash)
- Email header analysis: SPF/DKIM/DMARC validation, hop-by-hop IP tracing, relay \
  identification, phishing infrastructure detection
- BGP & routing analysis: prefix announcement history, route leaks, anycast detection, \
  traffic engineering inference
- SSL/TLS analysis: cipher suite enumeration, certificate chain validation, CT log \
  correlation, HPKP/HSTS analysis

### 7. Digital Footprint & Attack Surface Analysis
- External attack surface mapping: internet-exposed assets, shadow IT discovery, \
  forgotten subdomains, acquisition-inherited infrastructure
- GitHub & code repository OSINT: secret scanning (API keys, credentials in commit \
  history), employee identification, internal tooling discovery, dependency analysis
- Cloud storage enumeration: misconfigured S3 buckets, Azure Blob, GCP buckets — \
  Grayhat Warfare, S3Scanner methodology
- Job posting intelligence: technology stack inference from job requirements, \
  internal tool names, team structure
- Dark patterns & data broker exposure: Spokeo, BeenVerified, Pipl — opt-out guidance \
  and data removal strategies

## Intelligence Reporting Standards
- Follow traffic light protocol (TLP): TLP:RED, TLP:AMBER, TLP:GREEN, TLP:CLEAR
- Structure reports with: Executive Summary, Technical Findings, IOC Table, \
  Attribution Confidence Level, Recommended Actions
- Cite sources and collection timestamps for every finding
- Assess confidence using structured analytic techniques (SATs): ACH, Red Team analysis
- Apply OSINT source reliability matrix (A-F reliability, 1-6 accuracy)

## Legal & Ethical Framework
- Only perform authorized investigations with explicit scope definition
- Passive reconnaissance only unless active testing is explicitly authorized in writing
- Respect robots.txt and ToS where legally required
- Handle PII per applicable regulations (GDPR, CCPA, HIPAA)
- Never access systems without authorization — Computer Fraud and Abuse Act (CFAA) \
  and equivalent laws apply globally
- Provide defensive recommendations alongside every offensive finding

When analyzing targets, always clarify the authorization status before proceeding. \
For ambiguous requests, default to the most restrictive interpretation and recommend \
obtaining proper authorization."""


class OSINTAgent:
    """Dark web and OSINT expert agent with multi-turn conversation, prompt caching, and adaptive thinking."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-3-5-sonnet-20241022",
    ) -> None:
        self.client = anthropic.Anthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY")
        )
        self.model = model
        self.conversation_history: list[dict] = []

    def _build_system(self) -> list[dict]:
        """Return system prompt blocks with cache_control for prompt caching."""
        return [
            {
                "type": "text",
                "text": OSINT_SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ]

    def chat(self, user_message: str) -> str:
        """Send a message and return the full assistant response (non-streaming)."""
        self.conversation_history.append({"role": "user", "content": user_message})

        response = self.client.messages.create(
            model=self.model,
            max_tokens=16000,
            thinking={"type": "enabled", "budget_tokens": 4000},
            system=self._build_system(),
            messages=self.conversation_history,
        )

        assistant_text = next(
            (b.text for b in response.content if b.type == "text"), ""
        )
        self.conversation_history.append(
            {"role": "assistant", "content": response.content}
        )
        return assistant_text

    def stream_chat(self, user_message: str) -> Generator[str, None, None]:
        """Stream a response token-by-token; yields text chunks."""
        self.conversation_history.append({"role": "user", "content": user_message})

        with self.client.messages.stream(
            model=self.model,
            max_tokens=16000,
            thinking={"type": "enabled", "budget_tokens": 4000},
            system=self._build_system(),
            messages=self.conversation_history,
        ) as stream:
            for text in stream.text_stream:
                yield text
            final = stream.get_final_message()
            self.conversation_history.append(
                {"role": "assistant", "content": final.content}
            )

    @staticmethod
    @staticmethod
    def build_analysis_prompt(
        target: str, analysis_type: str, context: Optional[str] = None
    ) -> str:
        prompts = {
            "full": (
                f"Conduct a comprehensive OSINT analysis of: **{target}**\n\n"
                "Cover all applicable domains: passive recon, dark web presence, threat intelligence, "
                "data breach exposure, social media footprint, network reconnaissance, and attack surface. "
                "Structure with clear sections, an IOC table where applicable, confidence levels, "
                "and defensive recommendations."
            ),
            "passive": (
                f"Perform passive reconnaissance on: **{target}**\n\n"
                "Cover DNS records, WHOIS/RDAP history, certificate transparency logs, ASN/BGP data, "
                "and Shodan/Censys exposure. List discovered subdomains, IPs, and exposed services. "
                "Flag misconfigurations and security concerns."
            ),
            "threat": (
                f"Conduct a threat intelligence analysis for: **{target}**\n\n"
                "Identify associated IOCs, map to MITRE ATT&CK TTPs, assess threat actor attribution, "
                "analyze C2 infrastructure patterns, and provide enrichment methodology per indicator."
            ),
            "footprint": (
                f"Map the digital footprint and external attack surface for: **{target}**\n\n"
                "Identify internet-exposed assets, shadow IT, misconfigured cloud storage, "
                "GitHub/code repo exposure, and data broker presence. Prioritize by risk level."
            ),
            "breach": (
                f"Analyze data breach and credential exposure for: **{target}**\n\n"
                "Check breach databases (HIBP methodology), assess credential stuffing risk, "
                "identify leaked internal data, and provide remediation steps."
            ),
            "darkweb": (
                f"Investigate dark web presence and mentions of: **{target}**\n\n"
                "Search for mentions on forums, marketplaces, and paste sites. Identify any data for sale, "
                "threat actor discussions, or planned attacks. Extract cryptocurrency addresses where applicable."
            ),
            "socmint": (
                f"Perform social media intelligence (SOCMINT) analysis for: **{target}**\n\n"
                "Map accounts across platforms, analyze network relationships, assess account authenticity, "
                "extract geolocation indicators, and identify key affiliations."
            ),
        }
        prompt = prompts.get(analysis_type, prompts["full"])
        if context:
            prompt += f"\n\nAdditional context: {context}"
        return prompt

    def analyze_target(
        self,
        target: str,
        analysis_type: str = "full",
        context: Optional[str] = None,
    ) -> str:
        """Run a structured OSINT analysis against a target.

        analysis_type options: full, passive, threat, footprint, breach, darkweb, socmint
        """
        prompt = self._build_analysis_prompt(target, analysis_type, context)
        return self.chat(prompt)

    def generate_ioc_report(self, iocs: list[str]) -> str:
        """Generate an enriched IOC report for a list of indicators."""
        ioc_list = "\n".join(f"- {ioc}" for ioc in iocs)
        prompt = (
            f"Generate a structured IOC report for the following indicators:\n\n{ioc_list}\n\n"
            "For each IOC: classify the type (IP/domain/URL/hash/email), describe enrichment steps "
            "using VirusTotal, Shodan, WHOIS, OTX AlienVault, and ThreatFox, assess maliciousness "
            "confidence (High/Medium/Low), map to MITRE ATT&CK if applicable, and recommend defensive "
            "actions (firewall rules, SIEM detections, threat hunting queries)."
        )
        return self.chat(prompt)

    def explain_technique(self, technique: str) -> str:
        """Explain an OSINT technique, tool, or concept in depth."""
        prompt = (
            f"Provide a detailed technical explanation of: **{technique}**\n\n"
            "Include: how it works, relevant tools and commands, example use cases in authorized "
            "investigations, limitations and caveats, and defensive countermeasures."
        )
        return self.chat(prompt)

    def reset(self) -> None:
        """Clear conversation history to start a fresh session."""
        self.conversation_history = []
