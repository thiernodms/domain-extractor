"""
Module de détection et transformation de domaines en URLs.

Ce module extrait les domaines et sous-domaines d'un texte et les transforme
en URLs valides en respectant les principes Clean Code et SOLID.
"""

import re
from abc import ABC, abstractmethod
from typing import List, Set
from urllib.parse import urlparse, urlunparse
import tldextract


class DomainExtractor(ABC):
    """Interface pour l'extraction de domaines."""
    
    @abstractmethod
    def extract_domains(self, text: str) -> List[str]:
        """Extrait les domaines d'un texte."""
        pass


class URLTransformer(ABC):
    """Interface pour la transformation de domaines en URLs."""
    
    @abstractmethod
    def transform_to_urls(self, domains: List[str]) -> List[str]:
        """Transforme une liste de domaines en URLs valides."""
        pass


class TextDomainExtractor(DomainExtractor):
    """Extracteur de domaines à partir de texte."""
    
    def __init__(self):
        # Pattern pour détecter les domaines potentiels
        self._domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        )
    
    def extract_domains(self, text: str) -> List[str]:
        """
        Extrait les domaines valides d'un texte.
        
        Args:
            text: Le texte à analyser
            
        Returns:
            Liste des domaines valides trouvés
        """
        if not text:
            return []
        
        # Trouver tous les domaines potentiels
        potential_domains = self._domain_pattern.findall(text)
        
        # Valider et nettoyer les domaines
        valid_domains = self._validate_domains(potential_domains)
        
        # Retourner une liste unique (sans doublons)
        return list(set(valid_domains))
    
    def _validate_domains(self, potential_domains: List[str]) -> List[str]:
        """Valide les domaines en utilisant tldextract."""
        valid_domains = []
        
        for domain in potential_domains:
            extracted = tldextract.extract(domain)
            
            # Vérifier que le domaine a au moins un TLD valide
            if extracted.suffix and (extracted.domain or extracted.subdomain):
                # Reconstruire le domaine complet
                if extracted.subdomain:
                    full_domain = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}"
                else:
                    full_domain = f"{extracted.domain}.{extracted.suffix}"
                
                valid_domains.append(full_domain)
        
        return valid_domains


class StandardURLTransformer(URLTransformer):
    """Transformateur standard de domaines en URLs."""
    
    def __init__(self, default_scheme: str = "https"):
        self._default_scheme = default_scheme
    
    def transform_to_urls(self, domains: List[str]) -> List[str]:
        """
        Transforme les domaines en URLs valides.
        
        Args:
            domains: Liste des domaines à transformer
            
        Returns:
            Liste des URLs valides
        """
        if not domains:
            return []
        
        urls = []
        for domain in domains:
            url = self._create_url(domain)
            if self._is_valid_url(url):
                urls.append(url)
        
        return urls
    
    def _create_url(self, domain: str) -> str:
        """Crée une URL à partir d'un domaine."""
        if not domain.startswith(('http://', 'https://')):
            return f"{self._default_scheme}://{domain}"
        return domain
    
    def _is_valid_url(self, url: str) -> bool:
        """Valide une URL en utilisant urllib."""
        try:
            parsed = urlparse(url)
            return all([parsed.scheme, parsed.netloc])
        except Exception:
            return False


class DomainDetectionModule:
    """
    Module principal pour la détection de domaines et transformation en URLs.
    
    Cette classe orchestre le processus complet d'extraction et de transformation.
    """
    
    def __init__(self, 
                 extractor: DomainExtractor = None, 
                 transformer: URLTransformer = None):
        """
        Initialise le module avec des extracteurs et transformateurs personnalisés.
        
        Args:
            extractor: Extracteur de domaines (par défaut: TextDomainExtractor)
            transformer: Transformateur d'URLs (par défaut: StandardURLTransformer)
        """
        self._extractor = extractor or TextDomainExtractor()
        self._transformer = transformer or StandardURLTransformer()
    
    def process_text(self, text: str) -> List[str]:
        """
        Traite un texte pour extraire les domaines et les transformer en URLs.
        
        Args:
            text: Le texte à analyser
            
        Returns:
            Liste des URLs extraites et transformées
        """
        if not text:
            return []
        
        # Étape 1: Extraire les domaines
        domains = self._extractor.extract_domains(text)
        
        # Étape 2: Transformer en URLs
        urls = self._transformer.transform_to_urls(domains)
        
        return urls


# Fonction utilitaire pour une utilisation simple
def extract_urls_from_text(text: str) -> List[str]:
    """
    Fonction utilitaire pour extraire rapidement les URLs d'un texte.
    
    Args:
        text: Le texte à analyser
        
    Returns:
        Liste des URLs extraites
    """
    module = DomainDetectionModule()
    return module.process_text(text)

