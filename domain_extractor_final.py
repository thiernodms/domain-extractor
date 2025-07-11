#!/usr/bin/env python3
"""
Final domain extraction with URL transformation for ALL domains and subdomains.
Includes detailed display of found domains before transformation.

Features:
- Extracts ALL domains and subdomains from text
- Transforms ALL found domains to URLs (not just main domains)
- Detailed display: shows found domains first, then transformations
- Uses only Python standard library + tldextract

"""

import re
import tldextract
from urllib.parse import urlparse, urlunparse
from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum


# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    """Simple configuration constants."""
    DOMAIN_PATTERN = r'(?:https?://)?(?:www\.)?([a-zA-Z0-9](?:[a-zA-Z0-9\-\.]*[a-zA-Z0-9])?\.[a-zA-Z]{2,})(?:[/\?\#][^\s]*)?'
    CONTROL_CHARS = r'[\x00-\x1f\x7f-\x9f]'
    WHITESPACE = r'\s+'


class UrlStrategy(str, Enum):
    """URL transformation strategies."""
    SECURE_FIRST = "secure_first"
    FORCE_SECURE = "force_secure"
    PRESERVE_ORIGINAL = "preserve_original"
    FORCE_INSECURE = "force_insecure"


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class Domain:
    """Domain representation with enhanced classification."""
    full_domain: str
    subdomain: Optional[str]
    domain: str
    tld: str
    position: int
    original_text: str  # Original text where domain was found
    
    @property
    def has_subdomain(self) -> bool:
        """Check if domain has subdomain."""
        return self.subdomain is not None and self.subdomain != ""
    
    @property
    def is_complex_tld(self) -> bool:
        """Check if TLD contains dots."""
        return '.' in self.tld
    
    @property
    def domain_type(self) -> str:
        """Get domain type for display."""
        if self.has_subdomain:
            return "Sous-domaine"
        else:
            return "Domaine principal"
    
    @property
    def display_name(self) -> str:
        """Get display name for domain."""
        if self.has_subdomain:
            return f"{self.subdomain}.{self.domain}.{self.tld}"
        else:
            return f"{self.domain}.{self.tld}"


@dataclass
class Url:
    """URL representation with transformation details."""
    original: str
    transformed: str
    protocol: str
    domain: str
    path: Optional[str] = None
    query: Optional[str] = None
    fragment: Optional[str] = None
    transformation_applied: str = ""  # Description of transformation
    
    @property
    def is_secure(self) -> bool:
        """Check if URL uses HTTPS."""
        return self.protocol == "https"
    
    @property
    def has_components(self) -> bool:
        """Check if URL has additional components."""
        return any([self.path, self.query, self.fragment])
    
    @property
    def security_icon(self) -> str:
        """Get security icon for display."""
        return "🔒" if self.is_secure else "🔓"


@dataclass
class ExtractionResults:
    """Enhanced results with detailed categorization."""
    domains: List[Domain]
    urls: List[Url]
    
    @property
    def total_domains(self) -> int:
        """Total number of domains (including subdomains)."""
        return len(self.domains)
    
    @property
    def main_domains(self) -> List[Domain]:
        """List of main domains only."""
        return [d for d in self.domains if not d.has_subdomain]
    
    @property
    def subdomains(self) -> List[Domain]:
        """List of subdomains only."""
        return [d for d in self.domains if d.has_subdomain]
    
    @property
    def total_main_domains(self) -> int:
        """Number of main domains."""
        return len(self.main_domains)
    
    @property
    def total_subdomains(self) -> int:
        """Number of subdomains."""
        return len(self.subdomains)
    
    @property
    def total_urls(self) -> int:
        """Total number of URLs."""
        return len(self.urls)
    
    @property
    def secure_urls(self) -> int:
        """Number of secure URLs."""
        return sum(1 for url in self.urls if url.is_secure)
    
    @property
    def security_ratio(self) -> float:
        """Ratio of secure URLs."""
        return self.secure_urls / self.total_urls if self.total_urls > 0 else 0.0
    
    @property
    def unique_tlds(self) -> List[str]:
        """List of unique TLDs."""
        return sorted(set(domain.tld for domain in self.domains))
    
    def display_found_domains(self):
        """Display all found domains with categorization."""
        print(f"\n{'='*60}")
        print("DOMAINES ET SOUS-DOMAINES TROUVÉS")
        print(f"{'='*60}")
        
        if not self.domains:
            print("Aucun domaine trouvé dans le texte.")
            return
        
        print(f"Total trouvé: {self.total_domains} domaines")
        print(f"  • Domaines principaux: {self.total_main_domains}")
        print(f"  • Sous-domaines: {self.total_subdomains}")
        print(f"  • TLDs uniques: {len(self.unique_tlds)} ({', '.join(self.unique_tlds)})")
        
        # Display main domains
        if self.main_domains:
            print(f"\n📍 DOMAINES PRINCIPAUX ({len(self.main_domains)}):")
            for i, domain in enumerate(self.main_domains, 1):
                tld_info = f" (TLD complexe)" if domain.is_complex_tld else ""
                print(f"  {i}. {domain.display_name}{tld_info}")
                print(f"     └─ Trouvé dans: \"{domain.original_text}\"")
        
        # Display subdomains
        if self.subdomains:
            print(f"\n🌐 SOUS-DOMAINES ({len(self.subdomains)}):")
            for i, domain in enumerate(self.subdomains, 1):
                print(f"  {i}. {domain.display_name}")
                print(f"     ├─ Sous-domaine: {domain.subdomain}")
                print(f"     ├─ Domaine: {domain.domain}")
                print(f"     ├─ TLD: {domain.tld}")
                print(f"     └─ Trouvé dans: \"{domain.original_text}\"")
    
    def display_url_transformations(self, strategy: UrlStrategy):
        """Display URL transformations with details."""
        print(f"\n{'='*60}")
        print(f"TRANSFORMATION EN URLS - Stratégie: {strategy.value.upper()}")
        print(f"{'='*60}")
        
        if not self.urls:
            print("Aucune URL générée.")
            return
        
        print(f"URLs générées: {self.total_urls}")
        print(f"URLs sécurisées: {self.secure_urls} ({self.security_ratio:.1%})")
        print(f"URLs non-sécurisées: {self.total_urls - self.secure_urls}")
        
        # Group by transformation type
        transformations = {}
        for url in self.urls:
            trans_type = url.transformation_applied
            if trans_type not in transformations:
                transformations[trans_type] = []
            transformations[trans_type].append(url)
        
        print(f"\n🔄 TRANSFORMATIONS APPLIQUÉES:")
        for trans_type, urls in transformations.items():
            print(f"\n  📋 {trans_type} ({len(urls)} URLs):")
            for url in urls:
                print(f"    {url.security_icon} {url.original} → {url.transformed}")
                if url.has_components:
                    components = []
                    if url.path: components.append(f"chemin: {url.path}")
                    if url.query: components.append(f"paramètres: {url.query}")
                    if url.fragment: components.append(f"fragment: {url.fragment}")
                    print(f"      └─ Composants: {', '.join(components)}")


# =============================================================================
# INTERFACES
# =============================================================================

class TextProcessor(ABC):
    """Text processing interface."""
    
    @abstractmethod
    def clean(self, text: str) -> str:
        """Clean text for processing."""
        pass


class DomainExtractor(ABC):
    """Domain extraction interface."""
    
    @abstractmethod
    def extract_with_context(self, text: str) -> List[tuple]:
        """Extract domains with their original context."""
        pass


class DomainParser(ABC):
    """Domain parsing interface."""
    
    @abstractmethod
    def parse(self, domain: str, position: int, original_text: str) -> Domain:
        """Parse domain into components with context."""
        pass


class UrlTransformer(ABC):
    """URL transformation interface."""
    
    @abstractmethod
    def transform_all(self, domains: List[Domain], strategy: UrlStrategy) -> List[Url]:
        """Transform ALL domains (including subdomains) to URLs."""
        pass


# =============================================================================
# IMPLEMENTATIONS
# =============================================================================

class StandardTextProcessor(TextProcessor):
    """Text processor using only standard library."""
    
    def clean(self, text: str) -> str:
        """Clean text using standard library regex."""
        if not text or not isinstance(text, str):
            return ""
        
        # Remove control characters
        cleaned = re.sub(Config.CONTROL_CHARS, ' ', text)
        # Normalize whitespace
        return re.sub(Config.WHITESPACE, ' ', cleaned).strip()


class EnhancedDomainExtractor(DomainExtractor):
    """Enhanced domain extractor that captures context."""
    
    def __init__(self):
        self.extractor = tldextract.TLDExtract(
            cache_dir=None,
            include_psl_private_domains=True
        )
        self.pattern = re.compile(Config.DOMAIN_PATTERN, re.IGNORECASE)
    
    def extract_with_context(self, text: str) -> List[tuple]:
        """Extract domains with their surrounding context."""
        results = []
        
        # Find all matches with their positions
        for match in self.pattern.finditer(text):
            potential_domain = match.group(1)
            start_pos = match.start()
            end_pos = match.end()
            
            # Get surrounding context (20 chars before and after)
            context_start = max(0, start_pos - 20)
            context_end = min(len(text), end_pos + 20)
            context = text[context_start:context_end].strip()
            
            try:
                extracted = self.extractor(potential_domain)
                if extracted.domain and extracted.suffix:
                    # Reconstruct full domain
                    if extracted.subdomain:
                        full_domain = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}"
                    else:
                        full_domain = f"{extracted.domain}.{extracted.suffix}"
                    
                    results.append((full_domain, start_pos, context))
            except Exception:
                continue
        
        # Remove duplicates while preserving order and context
        seen = set()
        unique_results = []
        for domain, pos, context in results:
            if domain not in seen:
                seen.add(domain)
                unique_results.append((domain, pos, context))
        
        return unique_results


class ContextualDomainParser(DomainParser):
    """Domain parser that preserves context information."""
    
    def __init__(self):
        self.extractor = tldextract.TLDExtract(
            cache_dir=None,
            include_psl_private_domains=True
        )
    
    def parse(self, domain: str, position: int, original_text: str) -> Domain:
        """Parse domain with context preservation."""
        # Basic validation
        if not domain or not isinstance(domain, str):
            raise ValueError(f"Invalid domain: {domain}")
        
        # Extract domain from URL if needed
        if domain.startswith(('http://', 'https://')):
            parsed_url = urlparse(domain)
            domain_to_parse = parsed_url.netloc
        else:
            domain_to_parse = domain
        
        # Extract components
        extracted = self.extractor(domain_to_parse)
        
        if not extracted.domain or not extracted.suffix:
            raise ValueError(f"Could not parse domain: {domain}")
        
        return Domain(
            full_domain=domain,
            subdomain=extracted.subdomain if extracted.subdomain else None,
            domain=extracted.domain,
            tld=extracted.suffix,
            position=position,
            original_text=original_text
        )


class ComprehensiveUrlTransformer(UrlTransformer):
    """URL transformer that handles ALL domains and subdomains."""
    
    def transform_all(self, domains: List[Domain], strategy: UrlStrategy) -> List[Url]:
        """Transform ALL domains (including subdomains) to URLs."""
        urls = []
        
        for domain in domains:
            try:
                url = self._transform_single_domain(domain, strategy)
                urls.append(url)
            except Exception:
                continue
        
        return urls
    
    def _transform_single_domain(self, domain: Domain, strategy: UrlStrategy) -> Url:
        """Transform single domain to URL with transformation tracking."""
        original = domain.full_domain
        
        # Check if already a URL
        if original.startswith(('http://', 'https://')):
            return self._transform_existing_url(original, strategy, domain)
        else:
            return self._create_url_from_domain(original, strategy, domain)
    
    def _transform_existing_url(self, url: str, strategy: UrlStrategy, domain: Domain) -> Url:
        """Transform existing URL based on strategy."""
        parsed = urlparse(url)
        original_scheme = parsed.scheme
        
        # Determine new protocol and transformation description
        if strategy == UrlStrategy.FORCE_SECURE:
            new_scheme = "https"
            if original_scheme == "http":
                transformation = "Forcé HTTP → HTTPS"
            else:
                transformation = "HTTPS préservé"
        elif strategy == UrlStrategy.FORCE_INSECURE:
            new_scheme = "http"
            if original_scheme == "https":
                transformation = "Forcé HTTPS → HTTP"
            else:
                transformation = "HTTP préservé"
        elif strategy == UrlStrategy.PRESERVE_ORIGINAL:
            new_scheme = original_scheme
            transformation = f"Protocole original préservé ({original_scheme.upper()})"
        else:  # SECURE_FIRST
            if original_scheme == "http":
                new_scheme = "http"
                transformation = "HTTP existant préservé"
            else:
                new_scheme = "https"
                transformation = "HTTPS par défaut"
        
        # Reconstruct URL
        new_parsed = parsed._replace(scheme=new_scheme)
        transformed = urlunparse(new_parsed)
        
        return Url(
            original=url,
            transformed=transformed,
            protocol=new_scheme,
            domain=parsed.netloc,
            path=parsed.path if parsed.path else None,
            query=parsed.query if parsed.query else None,
            fragment=parsed.fragment if parsed.fragment else None,
            transformation_applied=transformation
        )
    
    def _create_url_from_domain(self, domain_str: str, strategy: UrlStrategy, domain: Domain) -> Url:
        """Create URL from domain string."""
        if strategy == UrlStrategy.FORCE_INSECURE:
            protocol = "http"
            transformation = "Nouveau domaine → HTTP"
        else:
            protocol = "https"  # Default to secure for all other strategies
            transformation = "Nouveau domaine → HTTPS"
        
        # Add domain type to transformation description
        if domain.has_subdomain:
            transformation += f" (sous-domaine: {domain.subdomain})"
        else:
            transformation += " (domaine principal)"
        
        transformed = f"{protocol}://{domain_str}"
        
        return Url(
            original=domain_str,
            transformed=transformed,
            protocol=protocol,
            domain=domain_str,
            transformation_applied=transformation
        )


# =============================================================================
# SERVICE
# =============================================================================

class FinalDomainService:
    """Final domain extraction service with comprehensive display."""
    
    def __init__(
        self,
        text_processor: TextProcessor,
        domain_extractor: DomainExtractor,
        domain_parser: DomainParser,
        url_transformer: UrlTransformer
    ):
        self.text_processor = text_processor
        self.domain_extractor = domain_extractor
        self.domain_parser = domain_parser
        self.url_transformer = url_transformer
    
    def extract_and_transform_all(
        self, 
        text: str, 
        url_strategy: UrlStrategy = UrlStrategy.SECURE_FIRST,
        display_details: bool = True
    ) -> ExtractionResults:
        """Extract ALL domains and transform to URLs with detailed display."""
        # Clean text
        cleaned_text = self.text_processor.clean(text)
        
        # Extract domains with context
        domain_contexts = self.domain_extractor.extract_with_context(cleaned_text)
        
        # Parse all domains (including subdomains)
        domains = []
        for i, (domain_str, position, context) in enumerate(domain_contexts):
            try:
                domain = self.domain_parser.parse(domain_str, position, context)
                domains.append(domain)
            except ValueError:
                continue
        
        # Transform ALL domains to URLs
        urls = self.url_transformer.transform_all(domains, url_strategy)
        
        # Create results
        results = ExtractionResults(domains=domains, urls=urls)
        
        # Display details if requested
        if display_details:
            results.display_found_domains()
            results.display_url_transformations(url_strategy)
        
        return results
    
    def extract_domains_from_text(self, text: str) -> Dict:
        """Backward compatibility method."""
        results = self.extract_and_transform_all(text, display_details=False)
        
        return {
            "total_domains": results.total_main_domains,
            "domains": [self._domain_to_dict(d) for d in results.main_domains],
            "subdomains": [self._domain_to_dict(d) for d in results.subdomains],
            "transformed_urls": [self._url_to_dict(u) for u in results.urls],
            "unique_tlds": results.unique_tlds,
            "summary": {
                "total_domains": results.total_main_domains,
                "total_subdomains": results.total_subdomains,
                "unique_tlds_count": len(results.unique_tlds),
                "total_urls": results.total_urls,
                "secure_urls": results.secure_urls,
                "security_ratio": results.security_ratio,
                "extraction_method": "tldextract"
            }
        }
    
    def _domain_to_dict(self, domain: Domain) -> Dict:
        """Convert domain to dictionary."""
        result = {
            "full_domain": domain.full_domain,
            "domain": domain.domain,
            "tld": domain.tld,
            "position": domain.position,
            "domain_type": domain.domain_type
        }
        if domain.has_subdomain:
            result["subdomain"] = domain.subdomain
        return result
    
    def _url_to_dict(self, url: Url) -> Dict:
        """Convert URL to dictionary."""
        return {
            "original_domain": url.original,
            "transformed_url": url.transformed,
            "protocol": url.protocol,
            "domain": url.domain,
            "is_secure": url.is_secure,
            "transformation_applied": url.transformation_applied,
            "has_path": url.path is not None,
            "has_query": url.query is not None,
            "has_fragment": url.fragment is not None
        }


# =============================================================================
# FACTORY
# =============================================================================

class ServiceFactory:
    """Factory for creating the final service."""
    
    @staticmethod
    def create_final() -> FinalDomainService:
        """Create final service with enhanced implementations."""
        return FinalDomainService(
            text_processor=StandardTextProcessor(),
            domain_extractor=EnhancedDomainExtractor(),
            domain_parser=ContextualDomainParser(),
            url_transformer=ComprehensiveUrlTransformer()
        )


# =============================================================================
# DEMO
# =============================================================================

class FinalDemo:
    """Final demonstration with comprehensive display."""
    
    def __init__(self, service: FinalDomainService):
        self.service = service
    
    def run_comprehensive_demo(self):
        """Run comprehensive demonstration."""
        sample_text = """
        Ressources de développement pour notre projet :
        
        🌐 Site principal: https://company.com
        📚 Documentation: docs.company.com  
        🔧 API principale: https://api.company.co.uk/v2
        📊 Tableau de bord: dashboard.analytics.company.com
        🎨 CDN: cdn.assets.company.com/static
        📱 App mobile: app.mobile.company.com
        🔒 Service auth: auth.secure.company.com/login
        
        Ressources externes:
        - GitHub: github.com/company/project
        - NPM: registry.npmjs.com/package/company-lib
        - Docs Python: docs.python.org
        - Monitoring: http://monitor.legacy.internal.com/health
        """
        
        print("=" * 80)
        print("EXTRACTEUR DE DOMAINES FINAL - DÉMONSTRATION COMPLÈTE")
        print("=" * 80)
        print(f"\nTexte d'exemple analysé :")
        print("-" * 40)
        print(sample_text.strip())
        
        # Test different strategies
        strategies = [
            UrlStrategy.SECURE_FIRST,
            UrlStrategy.FORCE_SECURE,
            UrlStrategy.PRESERVE_ORIGINAL
        ]
        
        for strategy in strategies:
            print(f"\n{'='*80}")
            print(f"ANALYSE AVEC STRATÉGIE: {strategy.value.upper()}")
            print(f"{'='*80}")
            
            results = self.service.extract_and_transform_all(
                sample_text, 
                strategy, 
                display_details=True
            )
            
            # Summary
            print(f"\n📊 RÉSUMÉ:")
            print(f"  • Total trouvé: {results.total_domains} domaines")
            print(f"  • Domaines principaux: {results.total_main_domains}")
            print(f"  • Sous-domaines: {results.total_subdomains}")
            print(f"  • URLs générées: {results.total_urls}")
            print(f"  • Sécurité: {results.security_ratio:.1%}")
    
    def run_simple_example(self):
        """Run simple usage example."""
        print(f"\n{'='*80}")
        print("EXEMPLE D'UTILISATION SIMPLE")
        print(f"{'='*80}")
        
        text = "Visitez notre site principal company.com, notre API api.service.fr et notre documentation docs.help.company.co.uk"
        print(f"Texte: {text}")
        
        results = self.service.extract_and_transform_all(
            text, 
            UrlStrategy.FORCE_SECURE,
            display_details=True
        )
        
        print(f"\n✅ Résultat: {results.total_domains} domaines transformés en {results.total_urls} URLs sécurisées")


def main():
    """Main function with comprehensive demonstration."""
    try:
        # Create service
        service = ServiceFactory.create_final()
        
        # Run comprehensive demonstration
        demo = FinalDemo(service)
        demo.run_comprehensive_demo()
        
        # Run simple example
        demo.run_simple_example()
        
        # Backward compatibility example
        print(f"\n{'='*80}")
        print("COMPATIBILITÉ DESCENDANTE")
        print(f"{'='*80}")
        
        text = "Visitez github.com et api.example.com"
        result_dict = service.extract_domains_from_text(text)
        print(f"Format dictionnaire: {result_dict['summary']['total_domains']} domaines principaux, {result_dict['summary']['total_subdomains']} sous-domaines")
        
    except Exception as error:
        print(f"Erreur: {error}")


if __name__ == "__main__":
    main()

