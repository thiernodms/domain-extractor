#!/usr/bin/env python3
"""
Domain and subdomain extraction script following SOLID principles and Clean Code practices.

This module provides a clean, maintainable solution for extracting domains from text
using tldextract for maximum accuracy with complex TLDs and private domains.

Author: Assistant Manus
Date: 2025-01-07
"""

import re
import tldextract
from abc import ABC, abstractmethod
from typing import List, Dict, Optional
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
class ExtractionResult:
    """Immutable extraction result container."""
    total_domains: int
    domains: List[Dict]
    subdomains: List[Dict]
    unique_tlds: List[str]
    summary: Dict
    
    @classmethod
    def empty(cls) -> 'ExtractionResult':
        """Create empty extraction result."""
        return cls(
            total_domains=0,
            domains=[],
            subdomains=[],
            unique_tlds=[],
            summary={
                'total_domains': 0,
                'total_subdomains': 0,
                'unique_tlds_count': 0,
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


class ResultFormatterInterface(ABC):
    """Interface for result formatting."""
    
    @abstractmethod
    def format_extraction_result(self, domains: List[DomainInfo]) -> ExtractionResult:
        """Format domain list into structured result."""
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
    
    def _create_tldextract_instance(self) -> tldextract.TLDExtract:
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


class StructuredResultFormatter(ResultFormatterInterface):
    """Formats extraction results into structured, immutable data."""
    
    def format_extraction_result(self, domains: List[DomainInfo]) -> ExtractionResult:
        """Format domain information into structured result."""
        if not domains:
            return ExtractionResult.empty()
        
        categorized_domains = self._categorize_domains(domains)
        unique_tlds = self._extract_unique_tlds(domains)
        summary = self._create_summary(categorized_domains, unique_tlds)
        
        return ExtractionResult(
            total_domains=len(domains),
            domains=categorized_domains['main_domains'],
            subdomains=categorized_domains['subdomains'],
            unique_tlds=unique_tlds,
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
    
    def _create_summary(self, categorized_domains: Dict, unique_tlds: List[str]) -> Dict:
        """Create summary statistics."""
        return {
            'total_domains': len(categorized_domains['main_domains']),
            'total_subdomains': len(categorized_domains['subdomains']),
            'unique_tlds_count': len(unique_tlds),
            'extraction_method': ExtractionMethod.TLDEXTRACT
        }


# =============================================================================
# ORCHESTRATION SERVICE (SOLID - Dependency Inversion Principle)
# =============================================================================

class DomainExtractionOrchestrator:
    """Orchestrates domain extraction workflow with injected dependencies."""
    
    def __init__(
        self,
        text_processor: TextProcessorInterface,
        domain_extractor: DomainExtractorInterface,
        domain_validator: DomainValidatorInterface,
        domain_parser: DomainParserInterface,
        result_formatter: ResultFormatterInterface
    ):
        self._text_processor = text_processor
        self._domain_extractor = domain_extractor
        self._domain_validator = domain_validator
        self._domain_parser = domain_parser
        self._result_formatter = result_formatter
    
    def extract_domains_from_text(self, text: str) -> ExtractionResult:
        """Execute complete domain extraction workflow."""
        try:
            cleaned_text = self._prepare_text(text)
            potential_domains = self._extract_potential_domains(cleaned_text)
            validated_domains = self._validate_and_parse_domains(potential_domains)
            return self._format_results(validated_domains)
        except Exception as error:
            raise DomainExtractionError(f"Domain extraction failed: {error}")
    
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
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Check if domain is valid."""
        return self._domain_validator.is_valid_domain(domain)
    
    def _parse_domain(self, domain: str, position: int) -> DomainInfo:
        """Parse domain into structured information."""
        return self._domain_parser.parse_domain(domain, position)
    
    def _format_results(self, domains: List[DomainInfo]) -> ExtractionResult:
        """Format results into structured output."""
        return self._result_formatter.format_extraction_result(domains)


# =============================================================================
# FACTORY (SOLID - Open/Closed Principle)
# =============================================================================

class DomainExtractionServiceFactory:
    """Factory for creating domain extraction services with clean dependencies."""
    
    @staticmethod
    def create_production_service() -> DomainExtractionOrchestrator:
        """Create production-ready domain extraction service."""
        return DomainExtractionOrchestrator(
            text_processor=CleanTextProcessor(),
            domain_extractor=TldExtractDomainExtractor(),
            domain_validator=RobustDomainValidator(),
            domain_parser=PreciseDomainParser(),
            result_formatter=StructuredResultFormatter()
        )
    
    @staticmethod
    def create_default_service() -> DomainExtractionOrchestrator:
        """Create default service (alias for production service)."""
        return DomainExtractionServiceFactory.create_production_service()


# =============================================================================
# DEMONSTRATION AND USAGE
# =============================================================================

class DomainExtractionDemo:
    """Demonstrates domain extraction capabilities with clean examples."""
    
    def __init__(self, service: DomainExtractionOrchestrator):
        self._service = service
    
    def run_comprehensive_demo(self) -> None:
        """Run comprehensive demonstration of extraction capabilities."""
        sample_text = self._get_sample_text()
        
        self._print_demo_header()
        self._print_sample_text(sample_text)
        
        results = self._extract_domains(sample_text)
        self._display_results(results)
        self._demonstrate_special_capabilities(results)
    
    def _get_sample_text(self) -> str:
        """Get sample text for demonstration."""
        return """
        Web resources and services:
        - Main site: https://www.google.com
        - Code repository: github.com/user/project
        - Project pages: username.github.io/docs
        - UK business: company.co.uk
        - API endpoint: api.service.fr/v1/data
        - Documentation: docs.python.org
        - Development server: test.dev.mysite.net
        - CDN: cdn.jsdelivr.net/npm/package
        - International: münchen.de
        """
    
    def _print_demo_header(self) -> None:
        """Print demonstration header."""
        print("=" * 60)
        print("CLEAN CODE DOMAIN EXTRACTOR WITH TLDEXTRACT")
        print("=" * 60)
    
    def _print_sample_text(self, text: str) -> None:
        """Print sample text being analyzed."""
        print("\nSAMPLE TEXT:")
        print(text)
        print("\n" + "-" * 60)
    
    def _extract_domains(self, text: str) -> ExtractionResult:
        """Extract domains from text."""
        return self._service.extract_domains_from_text(text)
    
    def _display_results(self, results: ExtractionResult) -> None:
        """Display extraction results."""
        self._print_summary(results)
        self._print_main_domains(results)
        self._print_subdomains(results)
        self._print_tld_analysis(results)
    
    def _print_summary(self, results: ExtractionResult) -> None:
        """Print results summary."""
        print(f"\nEXTRACTION SUMMARY:")
        print(f"Total domains found: {results.total_domains}")
        print(f"Main domains: {results.summary['total_domains']}")
        print(f"Subdomains: {results.summary['total_subdomains']}")
        print(f"Unique TLDs: {results.summary['unique_tlds_count']}")
        print(f"Method: {results.summary['extraction_method']}")
    
    def _print_main_domains(self, results: ExtractionResult) -> None:
        """Print main domains."""
        if results.domains:
            print(f"\nMAIN DOMAINS:")
            for domain in results.domains:
                print(f"  • {domain['full_domain']} → {domain['domain']}.{domain['tld']}")
    
    def _print_subdomains(self, results: ExtractionResult) -> None:
        """Print subdomains."""
        if results.subdomains:
            print(f"\nSUBDOMAINS:")
            for subdomain in results.subdomains:
                print(f"  • {subdomain['full_domain']} → {subdomain['subdomain']}.{subdomain['domain']}.{subdomain['tld']}")
    
    def _print_tld_analysis(self, results: ExtractionResult) -> None:
        """Print TLD analysis."""
        print(f"\nTLD ANALYSIS:")
        print(f"  Found TLDs: {', '.join(results.unique_tlds)}")
    
    def _demonstrate_special_capabilities(self, results: ExtractionResult) -> None:
        """Demonstrate special tldextract capabilities."""
        print(f"\nSPECIAL CAPABILITIES DEMONSTRATED:")
        
        special_cases = {
            "github.io": "Private domain (GitHub Pages)",
            "co.uk": "Compound TLD (UK commercial)",
            "jsdelivr.net": "Complex subdomain structure"
        }
        
        all_domains = results.domains + results.subdomains
        
        for domain_dict in all_domains:
            for special_tld, description in special_cases.items():
                if special_tld in domain_dict['tld'] or special_tld in domain_dict['full_domain']:
                    print(f"  ✅ {domain_dict['full_domain']} → {description}")


def main() -> None:
    """Main function demonstrating clean domain extraction."""
    try:
        service = DomainExtractionServiceFactory.create_default_service()
        demo = DomainExtractionDemo(service)
        demo.run_comprehensive_demo()
    except DomainExtractionError as error:
        print(f"Extraction error: {error}")
    except Exception as error:
        print(f"Unexpected error: {error}")


if __name__ == "__main__":
    main()

