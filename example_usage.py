"""
Exemple d'utilisation du module de détection de domaines.
"""

from domain_detection import extract_urls_from_text, DomainDetectionModule


def main():
    """Exemple d'utilisation simple."""
    
    # Exemple 1: Utilisation simple avec la fonction utilitaire
    print("=== Utilisation Simple ===")
    text = """
    Consultez notre documentation sur docs.example.com
    et notre API sur api.subdomain.example.org.
    Pour le support, visitez support.help.fr
    """
    
    urls = extract_urls_from_text(text)
    print(f"Texte: {text.strip()}")
    print(f"URLs extraites: {urls}")
    print()
    
    # Exemple 2: Utilisation avancée avec configuration personnalisée
    print("=== Utilisation Avancée ===")
    module = DomainDetectionModule()
    
    text2 = "Visitez github.com, stackoverflow.com et python.org pour apprendre"
    urls2 = module.process_text(text2)
    
    print(f"Texte: {text2}")
    print(f"URLs extraites: {urls2}")
    print()
    
    # Exemple 3: Traitement de plusieurs textes
    print("=== Traitement Multiple ===")
    texts = [
        "Site principal: www.monsite.com",
        "Blog: blog.exemple.fr et forum: forum.exemple.fr",
        "API: api.service.io"
    ]
    
    all_urls = []
    for i, text in enumerate(texts, 1):
        urls = extract_urls_from_text(text)
        print(f"Texte {i}: {text}")
        print(f"URLs: {urls}")
        all_urls.extend(urls)
    
    print(f"\nToutes les URLs collectées: {all_urls}")


if __name__ == "__main__":
    main()

