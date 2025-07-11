#!/usr/bin/env python3
"""
Script d'extraction de domaines et sous-domaines respectant les principes SOLID.
Version épurée utilisant uniquement tldextract pour une précision maximale.

"""

import re
import tldextract
from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum


class DomainType(Enum):
    """Types de domaines identifiés."""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"


@dataclass
class DomainInfo:
    """Informations sur un domaine extrait."""
    full_domain: str
    subdomain: Optional[str]
    domain: str
    tld: str
    domain_type: DomainType
    position: int


# ============================================================================
# INTERFACES (Dependency Inversion Principle)
# ============================================================================

class TextProcessorInterface(ABC):
    """Interface pour le traitement de texte."""
    
    @abstractmethod
    def clean_text(self, text: str) -> str:
        """Nettoie et prépare le texte pour l'extraction."""
        pass


class DomainExtractorInterface(ABC):
    """Interface pour l'extraction de domaines (Open/Closed Principle)."""
    
    @abstractmethod
    def extract_domains(self, text: str) -> List[str]:
        """Extrait les domaines du texte."""
        pass


class DomainValidatorInterface(ABC):
    """Interface pour la validation de domaines."""
    
    @abstractmethod
    def is_valid_domain(self, domain: str) -> bool:
        """Valide si une chaîne est un domaine valide."""
        pass


class DomainParserInterface(ABC):
    """Interface pour l'analyse de domaines."""
    
    @abstractmethod
    def parse_domain(self, domain: str, position: int) -> DomainInfo:
        """Analyse un domaine et retourne ses composants."""
        pass


class ResultFormatterInterface(ABC):
    """Interface pour le formatage des résultats."""
    
    @abstractmethod
    def format_results(self, domains: List[DomainInfo]) -> Dict:
        """Formate les résultats d'extraction."""
        pass


# ============================================================================
# IMPLÉMENTATIONS CONCRÈTES (Single Responsibility Principle)
# ============================================================================

class TextProcessor(TextProcessorInterface):
    """Traite et nettoie le texte d'entrée."""
    
    def clean_text(self, text: str) -> str:
        """Nettoie le texte en supprimant les caractères indésirables."""
        if not text:
            return ""
        
        # Supprime les caractères de contrôle et normalise les espaces
        cleaned = re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', text)
        cleaned = re.sub(r'\s+', ' ', cleaned)
        return cleaned.strip()


class TldExtractDomainExtractor(DomainExtractorInterface):
    """Extracteur de domaines utilisant la bibliothèque tldextract."""
    
    def __init__(self):
        # Configuration de tldextract
        self.extractor = tldextract.TLDExtract(
            cache_dir=None,  # Pas de cache pour éviter les problèmes de permissions
            include_psl_private_domains=True  # Inclut les domaines privés comme .github.io
        )
        
        # Pattern pour trouver les URLs et domaines potentiels
        self.url_pattern = re.compile(
            r'(?:https?://)?'  # Protocole optionnel
            r'(?:www\.)?'      # www optionnel
            r'([a-zA-Z0-9](?:[a-zA-Z0-9\-\.]*[a-zA-Z0-9])?'  # Domaine avec points
            r'\.[a-zA-Z]{2,})'  # TLD obligatoire
            r'(?:[/\?\#][^\s]*)?',  # Chemin/query/fragment optionnel
            re.IGNORECASE
        )
    
    def extract_domains(self, text: str) -> List[str]:
        """Extrait tous les domaines du texte en utilisant tldextract."""
        # Trouve tous les domaines potentiels
        potential_domains = self.url_pattern.findall(text)
        
        valid_domains = []
        for domain in potential_domains:
            try:
                # Utilise tldextract pour analyser le domaine
                extracted = self.extractor(domain)
                
                # Reconstruit le domaine complet si valide
                if extracted.domain and extracted.suffix:
                    if extracted.subdomain:
                        full_domain = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}"
                    else:
                        full_domain = f"{extracted.domain}.{extracted.suffix}"
                    
                    valid_domains.append(full_domain)
            except Exception:
                # Ignore les domaines qui ne peuvent pas être analysés
                continue
        
        return list(set(valid_domains))  # Supprime les doublons


class TldExtractDomainValidator(DomainValidatorInterface):
    """Validateur de domaines utilisant tldextract pour une validation précise."""
    
    def __init__(self):
        self.extractor = tldextract.TLDExtract(
            cache_dir=None,
            include_psl_private_domains=True
        )
    
    def is_valid_domain(self, domain: str) -> bool:
        """Vérifie si le domaine est valide en utilisant tldextract."""
        if not domain or len(domain) > 253:
            return False
        
        try:
            extracted = self.extractor(domain)
            
            # Un domaine est valide s'il a au moins un domaine et un suffixe
            if not extracted.domain or not extracted.suffix:
                return False
            
            # Vérifie la longueur des composants
            if len(extracted.domain) > 63:
                return False
            
            if extracted.subdomain and len(extracted.subdomain) > 63:
                return False
            
            # Vérifie les caractères valides
            for part in [extracted.subdomain, extracted.domain]:
                if part and not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$', part):
                    return False
            
            return True
            
        except Exception:
            return False


class TldExtractDomainParser(DomainParserInterface):
    """Analyseur de domaines utilisant tldextract pour une analyse précise."""
    
    def __init__(self):
        self.extractor = tldextract.TLDExtract(
            cache_dir=None,
            include_psl_private_domains=True
        )
    
    def parse_domain(self, domain: str, position: int) -> DomainInfo:
        """Analyse un domaine en utilisant tldextract."""
        try:
            extracted = self.extractor(domain)
            
            if not extracted.domain or not extracted.suffix:
                raise ValueError(f"Domaine invalide: {domain}")
            
            # Détermine le type
            if extracted.subdomain:
                domain_type = DomainType.SUBDOMAIN
                subdomain = extracted.subdomain
            else:
                domain_type = DomainType.DOMAIN
                subdomain = None
            
            return DomainInfo(
                full_domain=domain,
                subdomain=subdomain,
                domain=extracted.domain,
                tld=extracted.suffix,
                domain_type=domain_type,
                position=position
            )
            
        except Exception as e:
            raise ValueError(f"Impossible d'analyser le domaine {domain}: {str(e)}")


class ResultFormatter(ResultFormatterInterface):
    """Formateur de résultats avec informations détaillées."""
    
    def format_results(self, domains: List[DomainInfo]) -> Dict:
        """Formate les résultats en dictionnaire structuré."""
        results = {
            'total_domains': len(domains),
            'domains': [],
            'subdomains': [],
            'unique_tlds': set(),
            'summary': {}
        }
        
        for domain_info in domains:
            domain_dict = {
                'full_domain': domain_info.full_domain,
                'domain': domain_info.domain,
                'tld': domain_info.tld,
                'position': domain_info.position
            }
            
            if domain_info.domain_type == DomainType.SUBDOMAIN:
                domain_dict['subdomain'] = domain_info.subdomain
                results['subdomains'].append(domain_dict)
            else:
                results['domains'].append(domain_dict)
            
            results['unique_tlds'].add(domain_info.tld)
        
        # Convertit le set en liste pour la sérialisation JSON
        results['unique_tlds'] = list(results['unique_tlds'])
        
        # Statistiques
        results['summary'] = {
            'total_domains': len(results['domains']),
            'total_subdomains': len(results['subdomains']),
            'unique_tlds_count': len(results['unique_tlds']),
            'extraction_method': 'tldextract'
        }
        
        return results


# ============================================================================
# SERVICE PRINCIPAL (Dependency Inversion Principle)
# ============================================================================

class DomainExtractionService:
    """Service principal orchestrant l'extraction de domaines."""
    
    def __init__(
        self,
        text_processor: TextProcessorInterface,
        domain_extractor: DomainExtractorInterface,
        domain_validator: DomainValidatorInterface,
        domain_parser: DomainParserInterface,
        result_formatter: ResultFormatterInterface
    ):
        """Injection de dépendances pour respecter le DIP."""
        self.text_processor = text_processor
        self.domain_extractor = domain_extractor
        self.domain_validator = domain_validator
        self.domain_parser = domain_parser
        self.result_formatter = result_formatter
    
    def extract_domains_from_text(self, text: str) -> Dict:
        """Méthode principale d'extraction de domaines."""
        # 1. Nettoie le texte
        cleaned_text = self.text_processor.clean_text(text)
        
        # 2. Extrait les domaines potentiels
        potential_domains = self.domain_extractor.extract_domains(cleaned_text)
        
        # 3. Valide et analyse les domaines
        valid_domains = []
        for i, domain in enumerate(potential_domains):
            if self.domain_validator.is_valid_domain(domain):
                try:
                    domain_info = self.domain_parser.parse_domain(domain, i)
                    valid_domains.append(domain_info)
                except ValueError:
                    continue  # Ignore les domaines qui ne peuvent pas être analysés
        
        # 4. Formate les résultats
        return self.result_formatter.format_results(valid_domains)


# ============================================================================
# FACTORY PATTERN (Facilite l'instanciation)
# ============================================================================

class DomainExtractionServiceFactory:
    """Factory pour créer le service d'extraction avec tldextract."""
    
    @staticmethod
    def create_service() -> DomainExtractionService:
        """Crée un service utilisant tldextract."""
        return DomainExtractionService(
            text_processor=TextProcessor(),
            domain_extractor=TldExtractDomainExtractor(),
            domain_validator=TldExtractDomainValidator(),
            domain_parser=TldExtractDomainParser(),
            result_formatter=ResultFormatter()
        )
    
    @staticmethod
    def create_default_service() -> DomainExtractionService:
        """Crée un service par défaut (alias pour create_service)."""
        return DomainExtractionServiceFactory.create_service()


# ============================================================================
# INTERFACE UTILISATEUR
# ============================================================================

def main():
    """Fonction principale pour démonstration."""
    # Texte d'exemple complexe
    sample_text = """
    mlkdjfmlsdjfmlskdf
    sdfkjsdmlkfsd
    dfsldfsmkjsdlkfjsdmlfksdflksdfmlksdjfmklsdfjmsdlkfjqsdmlfkjsdmlfssddfdsfd
    Voici quelques sites web intéressants :
    - https://www.google.com pour les recherches
    - Le site github.com pour le code
    - Visitez subdomain.example.org pour plus d'infos
    - Contact: admin@company.co.uk
    - API disponible sur api.service.fr/v1/data
    - Documentation sur docs.python.org
    - Serveur de test: test.dev.mysite.net
    - CDN: cdn.jsdelivr.net/npm/package
    - Pages GitHub: username.github.io/project
    - Domaine international: münchen.de
    dsfkjsmdfljksd.dfkjdlf.com
    """
    
    print("=== EXTRACTEUR DE DOMAINES AVEC TLDEXTRACT ===\n")
    print("TEXTE À ANALYSER:")
    print(sample_text)
    print("\n" + "="*60 + "\n")
    
    # Crée le service
    service = DomainExtractionServiceFactory.create_default_service()
    
    # Extrait les domaines
    results = service.extract_domains_from_text(sample_text)
    
    # Affiche les résultats
    print("=== RÉSULTATS D'EXTRACTION ===\n")
    print(f"Total de domaines trouvés: {results['total_domains']}")
    print(f"Domaines principaux: {results['summary']['total_domains']}")
    print(f"Sous-domaines: {results['summary']['total_subdomains']}")
    print(f"TLD uniques: {results['summary']['unique_tlds_count']}")
    print(f"Méthode d'extraction: {results['summary']['extraction_method']}")
    
    print("\n--- DOMAINES PRINCIPAUX ---")
    for domain in results['domains']:
        print(f"  • {domain['full_domain']} (domaine: {domain['domain']}, TLD: {domain['tld']})")
    
    print("\n--- SOUS-DOMAINES ---")
    for subdomain in results['subdomains']:
        print(f"  • {subdomain['full_domain']} (sous-domaine: {subdomain['subdomain']}, domaine: {subdomain['domain']}, TLD: {subdomain['tld']})")
    
    print(f"\n--- TLD TROUVÉS ---")
    print(f"  {', '.join(results['unique_tlds'])}")
    
    # Démonstration des capacités avancées de tldextract
    print(f"\n--- ANALYSE DÉTAILLÉE ---")
    print("Capacités spéciales de tldextract :")
    
    special_cases = [
        "username.github.io",
        "company.co.uk", 
        "api.staging.service.co.uk",
        "cdn.jsdelivr.net"
    ]
    
    for case in special_cases:
        if any(case in d['full_domain'] for d in results['domains'] + results['subdomains']):
            domain_info = next((d for d in results['domains'] + results['subdomains'] if case in d['full_domain']), None)
            if domain_info:
                if 'subdomain' in domain_info:
                    print(f"  ✅ {case} → sous-domaine: '{domain_info['subdomain']}', domaine: '{domain_info['domain']}', TLD: '{domain_info['tld']}'")
                else:
                    print(f"  ✅ {case} → domaine: '{domain_info['domain']}', TLD: '{domain_info['tld']}'")


if __name__ == "__main__":
    main()

