#!/usr/bin/env python3
"""
Domain and subdomain extraction script with URL transformation capabilities.
Follows SOLID principles and Clean Code practices.

This module provides a clean, maintainable solution for extracting domains from text
and transforming them into valid URLs using tldextract for maximum accuracy.

Author: Assistant Manus
Date: 2025-01-07
"""

import re
import tldextract
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Union
from dataclasses import dataclass
from enum import Enum


# =============================================================================
# CONSTANTS AND CONFIGURATION
# =============================================================================

class DomainConstants:
    """Domain-related constants following Clean Code naming conventions."""
    
    MAX_DOMAIN_LENGTH = 253
    MAX_LABEL_LENGTH = 63
    MIN_TLD_LENGTH = 2
    
    CONTROL_CHARS_PATTERN = r'[\x00-\x1f\x7f-\x9f]'
    WHITESPACE_PATTERN = r'\s+'
    DOMAIN_CHAR_PATTERN = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$'
    
    URL_EXTRACTION_PATTERN = (
        r'(?:https?://)?'
        r'(?:www\.)?'
        r'([a-zA-Z0-9](?:[a-zA-Z0-9\-\.]*[a-zA-Z0-9])?'
        r'\.[a-zA-Z]{2,})'
        r'(?:[/\?\#][^\s]*)?'
    )


class ExtractionMethod:
    """Extraction method identifier."""
    TLDEXTRACT = "tldextract"


class UrlProtocol(Enum):
    """URL protocol types."""
    HTTP = "http"
    HTTPS = "https"


class UrlTransformationStrategy(Enum):
    """URL transformation strategies."""
    SECURE_FIRST = "secure_first"  # Prefer HTTPS
    PRESERVE_ORIGINAL = "preserve_original"  # Keep original if detected
    FORCE_SECURE = "force_secure"  # Always use HTTPS
    FORCE_INSECURE = "force_insecure"  # Always use HTTP


# =============================================================================
# DOMAIN MODELS
# =============================================================================

class DomainType(Enum):
    """Domain classification types."""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"


@dataclass(frozen=True)
class DomainInfo:
    """Immutable domain information container."""
    full_domain: str
    subdomain: Optional[str]
    domain: str
    tld: str
    domain_type: DomainType
    position: int
    
    def has_subdomain(self) -> bool:
        """Check if domain has subdomain."""
        return self.subdomain is not None
    
    def is_complex_tld(self) -> bool:
        """Check if domain uses complex TLD (contains dot)."""
        return '.' in self.tld


@dataclass(frozen=True)
class UrlInfo:
    """Immutable URL information container."""
    original_url: str
    protocol: UrlProtocol
    domain: str
    path: Optional[str]
    query: Optional[str]
    fragment: Optional[str]
    
    def get_full_url(self) -> str:
        """Reconstruct full URL from components."""
        url = f"{self.protocol.value}://{self.domain}"
        
        if self.path:
            url += self.path
        if self.query:
            url += f"?{self.query}"
        if self.fragment:
            url += f"#{self.fragment}"
            
        return url
    
    def is_secure(self) -> bool:
        """Check if URL uses HTTPS protocol."""
        return self.protocol == UrlProtocol.HTTPS


@dataclass(frozen=True)
class ExtractionResult:
    """Immutable extraction result container with URL transformation."""
    total_domains: int
    domains: List[Dict]
    subdomains: List[Dict]
    unique_tlds: List[str]
    transformed_urls: List[Dict]
    summary: Dict
    
    @classmethod
    def empty(cls) -> 'ExtractionResult':
        """Create empty extraction result."""
        return cls(
            total_domains=0,
            domains=[],
            subdomains=[],
            unique_tlds=[],
            transformed_urls=[],
            summary={
                'total_domains': 0,
                'total_subdomains': 0,
                'unique_tlds_count': 0,
                'total_urls': 0,
                'secure_urls': 0,
                'insecure_urls': 0,
                'security_ratio': 0.0,
                'extraction_method': ExtractionMethod.TLDEXTRACT
            }
        )


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================

class DomainExtractionError(Exception):
    """Base exception for domain extraction errors."""
    pass


class InvalidDomainError(DomainExtractionError):
    """Raised when domain validation fails."""
    pass


class DomainParsingError(DomainExtractionError):
    """Raised when domain parsing fails."""
    pass


class UrlTransformationError(DomainExtractionError):
    """Raised when URL transformation fails."""
    pass


# =============================================================================
# INTERFACES (SOLID - Dependency Inversion Principle)
# =============================================================================

class TextProcessorInterface(ABC):
    """Interface for text processing operations."""
    
    @abstractmethod
    def clean_text(self, text: str) -> str:
        """Clean and prepare text for domain extraction."""
        pass


class DomainExtractorInterface(ABC):
    """Interface for domain extraction strategies."""
    
    @abstractmethod
    def extract_potential_domains(self, text: str) -> List[str]:
        """Extract potential domains from text."""
        pass


class DomainValidatorInterface(ABC):
    """Interface for domain validation."""
    
    @abstractmethod
    def is_valid_domain(self, domain: str) -> bool:
        """Validate domain format and structure."""
        pass


class DomainParserInterface(ABC):
    """Interface for domain parsing and analysis."""
    
    @abstractmethod
    def parse_domain(self, domain: str, position: int) -> DomainInfo:
        """Parse domain into structured information."""
        pass


class UrlTransformerInterface(ABC):
    """Interface for URL transformation operations."""
    
    @abstractmethod
    def transform_domain_to_url(self, domain: str, strategy: UrlTransformationStrategy) -> UrlInfo:
        """Transform domain into URL with specified strategy."""
        pass
    
    @abstractmethod
    def transform_domains_to_urls(self, domains: List[DomainInfo], 
                                 strategy: UrlTransformationStrategy) -> List[UrlInfo]:
        """Transform multiple domains into URLs."""
        pass


class ResultFormatterInterface(ABC):
    """Interface for result formatting."""
    
    @abstractmethod
    def format_extraction_result(self, domains: List[DomainInfo], 
                               urls: List[UrlInfo]) -> ExtractionResult:
        """Format domain list and URLs into structured result."""
        pass


# =============================================================================
# IMPLEMENTATIONS (SOLID - Single Responsibility Principle)
# =============================================================================

class CleanTextProcessor(TextProcessorInterface):
    """Processes and sanitizes input text for domain extraction."""
    
    def clean_text(self, text: str) -> str:
        """Remove control characters and normalize whitespace."""
        if not self._is_valid_input(text):
            return ""
        
        cleaned_text = self._remove_control_characters(text)
        return self._normalize_whitespace(cleaned_text)
    
    def _is_valid_input(self, text: str) -> bool:
        """Check if input text is valid for processing."""
        return text is not None and isinstance(text, str)
    
    def _remove_control_characters(self, text: str) -> str:
        """Remove control characters from text."""
        return re.sub(DomainConstants.CONTROL_CHARS_PATTERN, ' ', text)
    
    def _normalize_whitespace(self, text: str) -> str:
        """Normalize whitespace in text."""
        normalized = re.sub(DomainConstants.WHITESPACE_PATTERN, ' ', text)
        return normalized.strip()


class TldExtractDomainExtractor(DomainExtractorInterface):
    """Extracts domains using tldextract library for maximum accuracy."""
    
    def __init__(self):
        self._extractor = self._create_tldextract_instance()
        self._url_pattern = self._compile_url_pattern()
    
    def extract_potential_domains(self, text: str) -> List[str]:
        """Extract and validate domains using tldextract."""
        potential_domains = self._find_potential_domains(text)
        valid_domains = self._extract_valid_domains(potential_domains)
        return self._remove_duplicates(valid_domains)
    
    def _create_tldextract_instance(self):
        """Create configured tldextract instance."""
        return tldextract.TLDExtract(
            cache_dir=None,
            include_psl_private_domains=True
        )
    
    def _compile_url_pattern(self) -> re.Pattern:
        """Compile URL extraction pattern."""
        return re.compile(DomainConstants.URL_EXTRACTION_PATTERN, re.IGNORECASE)
    
    def _find_potential_domains(self, text: str) -> List[str]:
        """Find potential domain strings in text."""
        return self._url_pattern.findall(text)
    
    def _extract_valid_domains(self, potential_domains: List[str]) -> List[str]:
        """Extract valid domains using tldextract."""
        valid_domains = []
        
        for domain in potential_domains:
            try:
                extracted_domain = self._extract_domain_components(domain)
                if self._is_valid_extracted_domain(extracted_domain):
                    reconstructed_domain = self._reconstruct_domain(extracted_domain)
                    valid_domains.append(reconstructed_domain)
            except Exception:
                continue
        
        return valid_domains
    
    def _extract_domain_components(self, domain: str):
        """Extract domain components using tldextract."""
        return self._extractor(domain)
    
    def _is_valid_extracted_domain(self, extracted) -> bool:
        """Check if extracted domain has required components."""
        return bool(extracted.domain and extracted.suffix)
    
    def _reconstruct_domain(self, extracted) -> str:
        """Reconstruct full domain from components."""
        if extracted.subdomain:
            return f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}"
        return f"{extracted.domain}.{extracted.suffix}"
    
    def _remove_duplicates(self, domains: List[str]) -> List[str]:
        """Remove duplicate domains while preserving order."""
        return list(dict.fromkeys(domains))


class RobustDomainValidator(DomainValidatorInterface):
    """Validates domains using tldextract and RFC standards."""
    
    def __init__(self):
        self._extractor = tldextract.TLDExtract(
            cache_dir=None,
            include_psl_private_domains=True
        )
    
    def is_valid_domain(self, domain: str) -> bool:
        """Comprehensive domain validation."""
        if not self._has_valid_length(domain):
            return False
        
        try:
            extracted = self._extractor(domain)
            return self._validate_extracted_components(extracted)
        except Exception:
            return False
    
    def _has_valid_length(self, domain: str) -> bool:
        """Check domain length constraints."""
        return (
            domain and 
            isinstance(domain, str) and 
            len(domain) <= DomainConstants.MAX_DOMAIN_LENGTH
        )
    
    def _validate_extracted_components(self, extracted) -> bool:
        """Validate all domain components."""
        if not self._has_required_components(extracted):
            return False
        
        return (
            self._is_valid_component_length(extracted.domain) and
            self._is_valid_subdomain(extracted.subdomain) and
            self._are_valid_characters(extracted)
        )
    
    def _has_required_components(self, extracted) -> bool:
        """Check if domain has required components."""
        return bool(extracted.domain and extracted.suffix)
    
    def _is_valid_component_length(self, component: str) -> bool:
        """Check component length constraints."""
        return len(component) <= DomainConstants.MAX_LABEL_LENGTH
    
    def _is_valid_subdomain(self, subdomain: Optional[str]) -> bool:
        """Validate subdomain if present."""
        if subdomain is None:
            return True
        return len(subdomain) <= DomainConstants.MAX_LABEL_LENGTH
    
    def _are_valid_characters(self, extracted) -> bool:
        """Validate character patterns in domain components."""
        components_to_check = [extracted.subdomain, extracted.domain]
        valid_components = [comp for comp in components_to_check if comp]
        
        return all(
            re.match(DomainConstants.DOMAIN_CHAR_PATTERN, component)
            for component in valid_components
        )


class PreciseDomainParser(DomainParserInterface):
    """Parses domains into structured information using tldextract."""
    
    def __init__(self):
        self._extractor = tldextract.TLDExtract(
            cache_dir=None,
            include_psl_private_domains=True
        )
    
    def parse_domain(self, domain: str, position: int) -> DomainInfo:
        """Parse domain into structured components."""
        try:
            extracted = self._extract_components(domain)
            self._validate_extraction(extracted, domain)
            return self._create_domain_info(extracted, domain, position)
        except Exception as error:
            raise DomainParsingError(f"Failed to parse domain '{domain}': {error}")
    
    def _extract_components(self, domain: str):
        """Extract domain components."""
        return self._extractor(domain)
    
    def _validate_extraction(self, extracted, original_domain: str) -> None:
        """Validate extraction results."""
        if not extracted.domain or not extracted.suffix:
            raise InvalidDomainError(f"Invalid domain structure: {original_domain}")
    
    def _create_domain_info(self, extracted, 
                           original_domain: str, position: int) -> DomainInfo:
        """Create DomainInfo from extracted components."""
        domain_type = self._determine_domain_type(extracted)
        
        return DomainInfo(
            full_domain=original_domain,
            subdomain=extracted.subdomain,
            domain=extracted.domain,
            tld=extracted.suffix,
            domain_type=domain_type,
            position=position
        )
    
    def _determine_domain_type(self, extracted) -> DomainType:
        """Determine if domain is a subdomain or main domain."""
        return DomainType.SUBDOMAIN if extracted.subdomain else DomainType.DOMAIN


class IntelligentUrlTransformer(UrlTransformerInterface):
    """Transforms domains into URLs with intelligent strategy application."""
    
    def __init__(self):
        self._url_pattern = self._compile_full_url_pattern()
    
    def transform_domain_to_url(self, domain: str, strategy: UrlTransformationStrategy) -> UrlInfo:
        """Transform single domain into URL with specified strategy."""
        try:
            if self._is_already_url(domain):
                return self._parse_existing_url(domain, strategy)
            else:
                return self._create_url_from_domain(domain, strategy)
        except Exception as error:
            raise UrlTransformationError(f"Failed to transform domain '{domain}': {error}")
    
    def transform_domains_to_urls(self, domains: List[DomainInfo], 
                                 strategy: UrlTransformationStrategy) -> List[UrlInfo]:
        """Transform multiple domains into URLs."""
        transformed_urls = []
        
        for domain_info in domains:
            try:
                url_info = self.transform_domain_to_url(domain_info.full_domain, strategy)
                transformed_urls.append(url_info)
            except UrlTransformationError:
                continue
        
        return transformed_urls
    
    def _compile_full_url_pattern(self) -> re.Pattern:
        """Compile pattern to detect existing URLs."""
        return re.compile(r'^https?://', re.IGNORECASE)
    
    def _is_already_url(self, domain: str) -> bool:
        """Check if string is already a URL."""
        return bool(self._url_pattern.match(domain))
    
    def _parse_existing_url(self, url: str, strategy: UrlTransformationStrategy) -> UrlInfo:
        """Parse existing URL and apply transformation strategy."""
        parsed_components = self._extract_url_components(url)
        transformed_protocol = self._apply_protocol_strategy(
            parsed_components['protocol'], strategy
        )
        
        return UrlInfo(
            original_url=url,
            protocol=transformed_protocol,
            domain=parsed_components['domain'],
            path=parsed_components['path'],
            query=parsed_components['query'],
            fragment=parsed_components['fragment']
        )
    
    def _create_url_from_domain(self, domain: str, strategy: UrlTransformationStrategy) -> UrlInfo:
        """Create URL from domain using transformation strategy."""
        protocol = self._determine_protocol_for_domain(domain, strategy)
        
        return UrlInfo(
            original_url=domain,
            protocol=protocol,
            domain=domain,
            path=None,
            query=None,
            fragment=None
        )
    
    def _extract_url_components(self, url: str) -> Dict[str, Optional[str]]:
        """Extract components from existing URL."""
        # Simple URL parsing - could be enhanced with urllib.parse
        url_pattern = re.compile(
            r'^(https?)://([^/\?\#]+)(?:(/[^\?\#]*))?(?:\?([^\#]*))?(?:\#(.*))?$',
            re.IGNORECASE
        )
        
        match = url_pattern.match(url)
        if not match:
            raise UrlTransformationError(f"Invalid URL format: {url}")
        
        return {
            'protocol': match.group(1).lower(),
            'domain': match.group(2),
            'path': match.group(3),
            'query': match.group(4),
            'fragment': match.group(5)
        }
    
    def _apply_protocol_strategy(self, current_protocol: str, 
                               strategy: UrlTransformationStrategy) -> UrlProtocol:
        """Apply transformation strategy to protocol."""
        if strategy == UrlTransformationStrategy.PRESERVE_ORIGINAL:
            return UrlProtocol.HTTPS if current_protocol == 'http' else UrlProtocol.HTTP
        elif strategy == UrlTransformationStrategy.FORCE_SECURE:
            return UrlProtocol.HTTPS
        elif strategy == UrlTransformationStrategy.FORCE_INSECURE:
            return UrlProtocol.HTTP
        else:  # SECURE_FIRST
            return UrlProtocol.HTTPS
    
    def _determine_protocol_for_domain(self, domain: str, 
                                     strategy: UrlTransformationStrategy) -> UrlProtocol:
        """Determine protocol for domain based on strategy."""
        if strategy == UrlTransformationStrategy.FORCE_INSECURE:
            return UrlProtocol.HTTP
        elif self._should_use_secure_protocol(domain, strategy):
            return UrlProtocol.HTTPS
        else:
            return UrlProtocol.HTTP
    
    def _should_use_secure_protocol(self, domain: str, 
                                  strategy: UrlTransformationStrategy) -> bool:
        """Determine if domain should use HTTPS based on strategy and domain characteristics."""
        if strategy in [UrlTransformationStrategy.FORCE_SECURE, UrlTransformationStrategy.SECURE_FIRST]:
            return True
        return True  # Default to secure for modern web


class EnhancedResultFormatter(ResultFormatterInterface):
    """Formats extraction results with URL transformation data."""
    
    def format_extraction_result(self, domains: List[DomainInfo], 
                               urls: List[UrlInfo]) -> ExtractionResult:
        """Format domain information and URLs into structured result."""
        if not domains:
            return ExtractionResult.empty()
        
        categorized_domains = self._categorize_domains(domains)
        unique_tlds = self._extract_unique_tlds(domains)
        formatted_urls = self._format_urls(urls)
        summary = self._create_enhanced_summary(categorized_domains, unique_tlds, urls)
        
        return ExtractionResult(
            total_domains=len(domains),
            domains=categorized_domains['main_domains'],
            subdomains=categorized_domains['subdomains'],
            unique_tlds=unique_tlds,
            transformed_urls=formatted_urls,
            summary=summary
        )
    
    def _categorize_domains(self, domains: List[DomainInfo]) -> Dict[str, List[Dict]]:
        """Categorize domains into main domains and subdomains."""
        main_domains = []
        subdomains = []
        
        for domain_info in domains:
            domain_dict = self._create_domain_dict(domain_info)
            
            if domain_info.has_subdomain():
                domain_dict['subdomain'] = domain_info.subdomain
                subdomains.append(domain_dict)
            else:
                main_domains.append(domain_dict)
        
        return {
            'main_domains': main_domains,
            'subdomains': subdomains
        }
    
    def _create_domain_dict(self, domain_info: DomainInfo) -> Dict:
        """Create dictionary representation of domain info."""
        return {
            'full_domain': domain_info.full_domain,
            'domain': domain_info.domain,
            'tld': domain_info.tld,
            'position': domain_info.position
        }
    
    def _extract_unique_tlds(self, domains: List[DomainInfo]) -> List[str]:
        """Extract unique TLDs from domain list."""
        unique_tlds = {domain_info.tld for domain_info in domains}
        return sorted(unique_tlds)
    
    def _format_urls(self, urls: List[UrlInfo]) -> List[Dict]:
        """Format URL information into dictionary list."""
        return [
            {
                'original_domain': url_info.original_url,
                'transformed_url': url_info.get_full_url(),
                'protocol': url_info.protocol.value,
                'domain': url_info.domain,
                'is_secure': url_info.is_secure(),
                'has_path': url_info.path is not None,
                'has_query': url_info.query is not None,
                'has_fragment': url_info.fragment is not None
            }
            for url_info in urls
        ]
    
    def _create_enhanced_summary(self, categorized_domains: Dict, 
                               unique_tlds: List[str], urls: List[UrlInfo]) -> Dict:
        """Create enhanced summary with URL statistics."""
        secure_urls = sum(1 for url in urls if url.is_secure())
        
        return {
            'total_domains': len(categorized_domains['main_domains']),
            'total_subdomains': len(categorized_domains['subdomains']),
            'unique_tlds_count': len(unique_tlds),
            'total_urls': len(urls),
            'secure_urls': secure_urls,
            'insecure_urls': len(urls) - secure_urls,
            'security_ratio': secure_urls / len(urls) if urls else 0.0,
            'extraction_method': ExtractionMethod.TLDEXTRACT
        }


# =============================================================================
# ORCHESTRATION SERVICE (SOLID - Dependency Inversion Principle)
# =============================================================================

class EnhancedDomainExtractionOrchestrator:
    """Orchestrates domain extraction and URL transformation workflow."""
    
    def __init__(
        self,
        text_processor: TextProcessorInterface,
        domain_extractor: DomainExtractorInterface,
        domain_validator: DomainValidatorInterface,
        domain_parser: DomainParserInterface,
        url_transformer: UrlTransformerInterface,
        result_formatter: ResultFormatterInterface
    ):
        self._text_processor = text_processor
        self._domain_extractor = domain_extractor
        self._domain_validator = domain_validator
        self._domain_parser = domain_parser
        self._url_transformer = url_transformer
        self._result_formatter = result_formatter
    
    def extract_domains_and_transform_urls(
        self, 
        text: str, 
        url_strategy: UrlTransformationStrategy = UrlTransformationStrategy.SECURE_FIRST
    ) -> ExtractionResult:
        """Execute complete domain extraction and URL transformation workflow."""
        try:
            cleaned_text = self._prepare_text(text)
            potential_domains = self._extract_potential_domains(cleaned_text)
            validated_domains = self._validate_and_parse_domains(potential_domains)
            transformed_urls = self._transform_domains_to_urls(validated_domains, url_strategy)
            return self._format_results(validated_domains, transformed_urls)
        except Exception as error:
            raise DomainExtractionError(f"Domain extraction and URL transformation failed: {error}")
    
    def extract_domains_from_text(self, text: str) -> ExtractionResult:
        """Execute domain extraction workflow (backward compatibility)."""
        return self.extract_domains_and_transform_urls(text, UrlTransformationStrategy.SECURE_FIRST)
    
    def _prepare_text(self, text: str) -> str:
        """Prepare text for domain extraction."""
        return self._text_processor.clean_text(text)
    
    def _extract_potential_domains(self, text: str) -> List[str]:
        """Extract potential domains from cleaned text."""
        return self._domain_extractor.extract_potential_domains(text)
    
    def _validate_and_parse_domains(self, potential_domains: List[str]) -> List[DomainInfo]:
        """Validate and parse potential domains."""
        validated_domains = []
        
        for position, domain in enumerate(potential_domains):
            if self._is_valid_domain(domain):
                try:
                    parsed_domain = self._parse_domain(domain, position)
                    validated_domains.append(parsed_domain)
                except DomainParsingError:
                    continue
        
        return validated_domains
    
    def _transform_domains_to_urls(self, domains: List[DomainInfo], 
                                 strategy: UrlTransformationStrategy) -> List[UrlInfo]:
        """Transform domains to URLs using specified strategy."""
        return self._url_transformer.transform_domains_to_urls(domains, strategy)
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Check if domain is valid."""
        return self._domain_validator.is_valid_domain(domain)
    
    def _parse_domain(self, domain: str, position: int) -> DomainInfo:
        """Parse domain into structured information."""
        return self._domain_parser.parse_domain(domain, position)
    
    def _format_results(self, domains: List[DomainInfo], urls: List[UrlInfo]) -> ExtractionResult:
        """Format results into structured output."""
        return self._result_formatter.format_extraction_result(domains, urls)


# =============================================================================
# FACTORY (SOLID - Open/Closed Principle)
# =============================================================================

class EnhancedDomainExtractionServiceFactory:
    """Factory for creating enhanced domain extraction services with URL transformation."""
    
    @staticmethod
    def create_production_service() -> EnhancedDomainExtractionOrchestrator:
        """Create production-ready domain extraction service with URL transformation."""
        return EnhancedDomainExtractionOrchestrator(
            text_processor=CleanTextProcessor(),
            domain_extractor=TldExtractDomainExtractor(),
            domain_validator=RobustDomainValidator(),
            domain_parser=PreciseDomainParser(),
            url_transformer=IntelligentUrlTransformer(),
            result_formatter=EnhancedResultFormatter()
        )
    
    @staticmethod
    def create_default_service() -> EnhancedDomainExtractionOrchestrator:
        """Create default service (alias for production service)."""
        return EnhancedDomainExtractionServiceFactory.create_production_service()
    
    @staticmethod
    def create_custom_service(
        url_transformer: UrlTransformerInterface,
        url_strategy: UrlTransformationStrategy = UrlTransformationStrategy.SECURE_FIRST
    ) -> EnhancedDomainExtractionOrchestrator:
        """Create service with custom URL transformer."""
        return EnhancedDomainExtractionOrchestrator(
            text_processor=CleanTextProcessor(),
            domain_extractor=TldExtractDomainExtractor(),
            domain_validator=RobustDomainValidator(),
            domain_parser=PreciseDomainParser(),
            url_transformer=url_transformer,
            result_formatter=EnhancedResultFormatter()
        )


# =============================================================================
# DEMONSTRATION AND USAGE
# =============================================================================

class EnhancedDomainExtractionDemo:
    """Demonstrates enhanced domain extraction with URL transformation capabilities."""
    
    def __init__(self, service: EnhancedDomainExtractionOrchestrator):
        self._service = service
    
    def run_comprehensive_demo(self) -> None:
        """Run comprehensive demonstration of extraction and URL transformation."""
        sample_text = self._get_sample_text()
        
        self._print_demo_header()
        self._print_sample_text(sample_text)
        
        # Demonstrate different URL transformation strategies
        strategies = [
            UrlTransformationStrategy.SECURE_FIRST,
            UrlTransformationStrategy.FORCE_SECURE,
            UrlTransformationStrategy.PRESERVE_ORIGINAL
        ]
        
        for strategy in strategies:
            self._demonstrate_strategy(sample_text, strategy)
    
    def _get_sample_text(self) -> str:
        """Get sample text for demonstration."""
        return """
        Web resources and services:
        - Main site: https://www.google.com
        - Code repository: github.com/user/project
        - Project pages: username.github.io/docs
        - UK business: company.co.uk
        - API endpoint: http://api.service.fr/v1/data
        - Documentation: docs.python.org
        - Development server: test.dev.mysite.net
        - CDN: cdn.jsdelivr.net/npm/package
        - International: münchen.de
        """
    
    def _print_demo_header(self) -> None:
        """Print demonstration header."""
        print("=" * 70)
        print("ENHANCED CLEAN CODE DOMAIN EXTRACTOR WITH URL TRANSFORMATION")
        print("=" * 70)
    
    def _print_sample_text(self, text: str) -> None:
        """Print sample text being analyzed."""
        print("\nSAMPLE TEXT:")
        print(text)
        print("\n" + "-" * 70)
    
    def _demonstrate_strategy(self, text: str, strategy: UrlTransformationStrategy) -> None:
        """Demonstrate specific URL transformation strategy."""
        print(f"\n🔧 URL TRANSFORMATION STRATEGY: {strategy.value.upper()}")
        print("-" * 50)
        
        results = self._service.extract_domains_and_transform_urls(text, strategy)
        
        self._print_strategy_summary(results)
        self._print_transformed_urls(results)
    
    def _print_strategy_summary(self, results: ExtractionResult) -> None:
        """Print summary for specific strategy."""
        summary = results.summary
        print(f"Total URLs: {summary['total_urls']}")
        print(f"Secure URLs (HTTPS): {summary['secure_urls']}")
        print(f"Insecure URLs (HTTP): {summary['insecure_urls']}")
        print(f"Security Ratio: {summary['security_ratio']:.1%}")
    
    def _print_transformed_urls(self, results: ExtractionResult) -> None:
        """Print transformed URLs."""
        print("\nTRANSFORMED URLS:")
        for url_info in results.transformed_urls:
            security_indicator = "🔒" if url_info['is_secure'] else "🔓"
            print(f"  {security_indicator} {url_info['original_domain']} → {url_info['transformed_url']}")


def main() -> None:
    """Main function demonstrating enhanced domain extraction with URL transformation."""
    try:
        service = EnhancedDomainExtractionServiceFactory.create_default_service()
        demo = EnhancedDomainExtractionDemo(service)
        demo.run_comprehensive_demo()
    except DomainExtractionError as error:
        print(f"Extraction error: {error}")
    except Exception as error:
        print(f"Unexpected error: {error}")


if __name__ == "__main__":
    main()

