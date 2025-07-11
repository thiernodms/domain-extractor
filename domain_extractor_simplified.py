#!/usr/bin/env python3
"""
Simplified domain extraction with URL transformation using well-known libraries.
Maintains Clean Code and SOLID principles while reducing complexity.

Libraries used:
- tldextract: Domain parsing
- urllib.parse: URL parsing
- validators: Domain validation
- pydantic: Data models
- re: Pattern matching
- typing: Type hints

Author: Assistant Manus
Date: 2025-01-07
"""

import re
import tldextract
import validators
from urllib.parse import urlparse, urlunparse
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Union
from pydantic import BaseModel, Field, field_validator
from enum import Enum


# =============================================================================
# CONFIGURATION AND CONSTANTS
# =============================================================================

class Config:
    """Application configuration using simple constants."""
    MAX_DOMAIN_LENGTH = 253
    DEFAULT_PROTOCOL = "https"
    CONTROL_CHARS_PATTERN = r'[\x00-\x1f\x7f-\x9f]'
    DOMAIN_PATTERN = r'(?:https?://)?(?:www\.)?([a-zA-Z0-9](?:[a-zA-Z0-9\-\.]*[a-zA-Z0-9])?\.[a-zA-Z]{2,})(?:[/\?\#][^\s]*)?'


class UrlStrategy(str, Enum):
    """URL transformation strategies using string enum for simplicity."""
    SECURE_FIRST = "secure_first"
    FORCE_SECURE = "force_secure"
    PRESERVE_ORIGINAL = "preserve_original"
    FORCE_INSECURE = "force_insecure"


# =============================================================================
# PYDANTIC MODELS (Simplified Data Classes)
# =============================================================================

class DomainModel(BaseModel):
    """Simplified domain model using Pydantic for validation."""
    full_domain: str
    subdomain: Optional[str] = None
    domain: str
    tld: str
    position: int
    
    @field_validator('full_domain')
    @classmethod
    def validate_domain(cls, v):
        """Validate domain using validators library with URL support."""
        # Extract domain from URL if needed
        if v.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            parsed = urlparse(v)
            domain_to_validate = parsed.netloc
        else:
            domain_to_validate = v
        
        if not validators.domain(domain_to_validate):
            raise ValueError(f"Invalid domain: {v}")
        return v
    
    @property
    def has_subdomain(self) -> bool:
        """Check if domain has subdomain."""
        return self.subdomain is not None and self.subdomain != ""
    
    @property
    def is_complex_tld(self) -> bool:
        """Check if TLD is complex (contains dot)."""
        return '.' in self.tld


class UrlModel(BaseModel):
    """Simplified URL model using Pydantic."""
    original: str
    transformed: str
    protocol: str
    domain: str
    path: Optional[str] = None
    query: Optional[str] = None
    fragment: Optional[str] = None
    
    @property
    def is_secure(self) -> bool:
        """Check if URL is secure (HTTPS)."""
        return self.protocol == "https"
    
    @property
    def has_components(self) -> bool:
        """Check if URL has additional components."""
        return any([self.path, self.query, self.fragment])


class ExtractionResults(BaseModel):
    """Simplified results model using Pydantic."""
    domains: List[DomainModel] = Field(default_factory=list)
    urls: List[UrlModel] = Field(default_factory=list)
    
    @property
    def total_domains(self) -> int:
        """Total number of domains found."""
        return len(self.domains)
    
    @property
    def total_urls(self) -> int:
        """Total number of URLs generated."""
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
        """List of unique TLDs found."""
        return sorted(set(domain.tld for domain in self.domains))
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for backward compatibility."""
        return {
            "total_domains": self.total_domains,
            "domains": [self._domain_to_dict(d) for d in self.domains if not d.has_subdomain],
            "subdomains": [self._domain_to_dict(d) for d in self.domains if d.has_subdomain],
            "transformed_urls": [self._url_to_dict(u) for u in self.urls],
            "unique_tlds": self.unique_tlds,
            "summary": {
                "total_domains": len([d for d in self.domains if not d.has_subdomain]),
                "total_subdomains": len([d for d in self.domains if d.has_subdomain]),
                "unique_tlds_count": len(self.unique_tlds),
                "total_urls": self.total_urls,
                "secure_urls": self.secure_urls,
                "security_ratio": self.security_ratio,
                "extraction_method": "tldextract"
            }
        }
    
    def _domain_to_dict(self, domain: DomainModel) -> Dict:
        """Convert domain model to dictionary."""
        result = {
            "full_domain": domain.full_domain,
            "domain": domain.domain,
            "tld": domain.tld,
            "position": domain.position
        }
        if domain.has_subdomain:
            result["subdomain"] = domain.subdomain
        return result
    
    def _url_to_dict(self, url: UrlModel) -> Dict:
        """Convert URL model to dictionary."""
        return {
            "original_domain": url.original,
            "transformed_url": url.transformed,
            "protocol": url.protocol,
            "domain": url.domain,
            "is_secure": url.is_secure,
            "has_path": url.path is not None,
            "has_query": url.query is not None,
            "has_fragment": url.fragment is not None
        }


# =============================================================================
# SIMPLIFIED INTERFACES (SOLID - DIP)
# =============================================================================

class TextProcessor(ABC):
    """Simplified text processor interface."""
    
    @abstractmethod
    def clean(self, text: str) -> str:
        """Clean text for processing."""
        pass


class DomainExtractor(ABC):
    """Simplified domain extractor interface."""
    
    @abstractmethod
    def extract(self, text: str) -> List[str]:
        """Extract domains from text."""
        pass


class DomainParser(ABC):
    """Simplified domain parser interface."""
    
    @abstractmethod
    def parse(self, domain: str, position: int) -> DomainModel:
        """Parse domain into model."""
        pass


class UrlTransformer(ABC):
    """Simplified URL transformer interface."""
    
    @abstractmethod
    def transform(self, domains: List[DomainModel], strategy: UrlStrategy) -> List[UrlModel]:
        """Transform domains to URLs."""
        pass


# =============================================================================
# SIMPLIFIED IMPLEMENTATIONS
# =============================================================================

class SimpleTextProcessor(TextProcessor):
    """Simplified text processor using standard library."""
    
    def clean(self, text: str) -> str:
        """Clean text using simple regex operations."""
        if not text or not isinstance(text, str):
            return ""
        
        # Remove control characters and normalize whitespace
        cleaned = re.sub(Config.CONTROL_CHARS_PATTERN, ' ', text)
        return re.sub(r'\s+', ' ', cleaned).strip()


class TldExtractDomainExtractor(DomainExtractor):
    """Simplified domain extractor using tldextract."""
    
    def __init__(self):
        self.extractor = tldextract.TLDExtract(
            cache_dir=None,
            include_psl_private_domains=True
        )
        self.pattern = re.compile(Config.DOMAIN_PATTERN, re.IGNORECASE)
    
    def extract(self, text: str) -> List[str]:
        """Extract domains using regex and validate with tldextract."""
        potential_domains = self.pattern.findall(text)
        valid_domains = []
        
        for domain in potential_domains:
            try:
                extracted = self.extractor(domain)
                if extracted.domain and extracted.suffix:
                    # Reconstruct full domain
                    if extracted.subdomain:
                        full_domain = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}"
                    else:
                        full_domain = f"{extracted.domain}.{extracted.suffix}"
                    valid_domains.append(full_domain)
            except Exception:
                continue
        
        # Remove duplicates while preserving order
        return list(dict.fromkeys(valid_domains))


class ValidatingDomainParser(DomainParser):
    """Simplified domain parser using tldextract and validators."""
    
    def __init__(self):
        self.extractor = tldextract.TLDExtract(
            cache_dir=None,
            include_psl_private_domains=True
        )
    
    def parse(self, domain: str, position: int) -> DomainModel:
        """Parse domain using tldextract and validate with validators."""
        # Validate domain first
        if not validators.domain(domain):
            raise ValueError(f"Invalid domain: {domain}")
        
        # Extract components
        extracted = self.extractor(domain)
        
        return DomainModel(
            full_domain=domain,
            subdomain=extracted.subdomain if extracted.subdomain else None,
            domain=extracted.domain,
            tld=extracted.suffix,
            position=position
        )


class UrllibUrlTransformer(UrlTransformer):
    """Simplified URL transformer using urllib.parse."""
    
    def transform(self, domains: List[DomainModel], strategy: UrlStrategy) -> List[UrlModel]:
        """Transform domains to URLs using urllib.parse."""
        urls = []
        
        for domain in domains:
            try:
                url_model = self._transform_single_domain(domain, strategy)
                urls.append(url_model)
            except Exception:
                continue
        
        return urls
    
    def _transform_single_domain(self, domain: DomainModel, strategy: UrlStrategy) -> UrlModel:
        """Transform single domain to URL."""
        original = domain.full_domain
        
        # Check if already a URL
        if original.startswith(('http://', 'https://')):
            return self._transform_existing_url(original, strategy)
        else:
            return self._create_url_from_domain(original, strategy)
    
    def _transform_existing_url(self, url: str, strategy: UrlStrategy) -> UrlModel:
        """Transform existing URL based on strategy."""
        parsed = urlparse(url)
        
        # Determine new protocol based on strategy
        if strategy == UrlStrategy.FORCE_SECURE:
            new_scheme = "https"
        elif strategy == UrlStrategy.FORCE_INSECURE:
            new_scheme = "http"
        elif strategy == UrlStrategy.PRESERVE_ORIGINAL:
            new_scheme = parsed.scheme
        else:  # SECURE_FIRST
            new_scheme = "https" if parsed.scheme == "https" else "https"
        
        # Reconstruct URL
        new_parsed = parsed._replace(scheme=new_scheme)
        transformed = urlunparse(new_parsed)
        
        return UrlModel(
            original=url,
            transformed=transformed,
            protocol=new_scheme,
            domain=parsed.netloc,
            path=parsed.path if parsed.path else None,
            query=parsed.query if parsed.query else None,
            fragment=parsed.fragment if parsed.fragment else None
        )
    
    def _create_url_from_domain(self, domain: str, strategy: UrlStrategy) -> UrlModel:
        """Create URL from domain based on strategy."""
        if strategy == UrlStrategy.FORCE_INSECURE:
            protocol = "http"
        else:
            protocol = "https"  # Default to secure
        
        transformed = f"{protocol}://{domain}"
        
        return UrlModel(
            original=domain,
            transformed=transformed,
            protocol=protocol,
            domain=domain
        )


# =============================================================================
# SIMPLIFIED SERVICE (SOLID - DIP)
# =============================================================================

class SimplifiedDomainService:
    """Simplified domain extraction service with dependency injection."""
    
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
    
    def extract_domains_and_urls(
        self, 
        text: str, 
        url_strategy: UrlStrategy = UrlStrategy.SECURE_FIRST
    ) -> ExtractionResults:
        """Extract domains and transform to URLs."""
        # Clean text
        cleaned_text = self.text_processor.clean(text)
        
        # Extract potential domains
        potential_domains = self.domain_extractor.extract(cleaned_text)
        
        # Parse and validate domains
        domains = []
        for i, domain_str in enumerate(potential_domains):
            try:
                domain = self.domain_parser.parse(domain_str, i)
                domains.append(domain)
            except ValueError:
                continue
        
        # Transform to URLs
        urls = self.url_transformer.transform(domains, url_strategy)
        
        return ExtractionResults(domains=domains, urls=urls)
    
    def extract_domains_from_text(self, text: str) -> Dict:
        """Backward compatibility method."""
        results = self.extract_domains_and_urls(text)
        return results.to_dict()


# =============================================================================
# SIMPLIFIED FACTORY (SOLID - OCP)
# =============================================================================

class ServiceFactory:
    """Simplified factory for creating services."""
    
    @staticmethod
    def create_default() -> SimplifiedDomainService:
        """Create default service with standard implementations."""
        return SimplifiedDomainService(
            text_processor=SimpleTextProcessor(),
            domain_extractor=TldExtractDomainExtractor(),
            domain_parser=ValidatingDomainParser(),
            url_transformer=UrllibUrlTransformer()
        )
    
    @staticmethod
    def create_custom(
        text_processor: Optional[TextProcessor] = None,
        domain_extractor: Optional[DomainExtractor] = None,
        domain_parser: Optional[DomainParser] = None,
        url_transformer: Optional[UrlTransformer] = None
    ) -> SimplifiedDomainService:
        """Create service with custom components."""
        return SimplifiedDomainService(
            text_processor=text_processor or SimpleTextProcessor(),
            domain_extractor=domain_extractor or TldExtractDomainExtractor(),
            domain_parser=domain_parser or ValidatingDomainParser(),
            url_transformer=url_transformer or UrllibUrlTransformer()
        )


# =============================================================================
# SIMPLIFIED DEMO
# =============================================================================

class SimplifiedDemo:
    """Simplified demonstration of the service."""
    
    def __init__(self, service: SimplifiedDomainService):
        self.service = service
    
    def run_demo(self):
        """Run simplified demonstration."""
        sample_text = """
        Web resources:
        - GitHub: https://github.com/user/repo
        - API: http://api.service.fr/v1
        - Docs: docs.python.org
        - UK Site: company.co.uk
        - CDN: cdn.jsdelivr.net
        """
        
        print("=" * 60)
        print("SIMPLIFIED DOMAIN EXTRACTOR WITH URL TRANSFORMATION")
        print("=" * 60)
        print(f"\nSample text: {sample_text.strip()}")
        
        # Test different strategies
        strategies = [
            UrlStrategy.SECURE_FIRST,
            UrlStrategy.FORCE_SECURE,
            UrlStrategy.PRESERVE_ORIGINAL
        ]
        
        for strategy in strategies:
            print(f"\n🔧 Strategy: {strategy.value.upper()}")
            print("-" * 40)
            
            results = self.service.extract_domains_and_urls(sample_text, strategy)
            
            print(f"Domains found: {results.total_domains}")
            print(f"URLs generated: {results.total_urls}")
            print(f"Secure URLs: {results.secure_urls}")
            print(f"Security ratio: {results.security_ratio:.1%}")
            
            print("\nTransformed URLs:")
            for url in results.urls:
                security_icon = "🔒" if url.is_secure else "🔓"
                print(f"  {security_icon} {url.original} → {url.transformed}")


def main():
    """Main function with simplified usage."""
    try:
        # Create service using factory
        service = ServiceFactory.create_default()
        
        # Run demonstration
        demo = SimplifiedDemo(service)
        demo.run_demo()
        
        # Example of direct usage
        print(f"\n{'='*60}")
        print("DIRECT USAGE EXAMPLE")
        print(f"{'='*60}")
        
        text = "Visit github.com and https://api.example.com/v1"
        results = service.extract_domains_and_urls(text, UrlStrategy.FORCE_SECURE)
        
        print(f"Input: {text}")
        print(f"Found {results.total_domains} domains")
        print(f"Generated {results.total_urls} URLs ({results.security_ratio:.1%} secure)")
        
        for url in results.urls:
            print(f"  • {url.original} → {url.transformed}")
        
    except Exception as error:
        print(f"Error: {error}")


if __name__ == "__main__":
    main()

