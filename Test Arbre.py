def arbre_hashcat():
    """
    Arbre de décision pour identifier le hash et proposer commande Hashcat.
    """

    # Question initiale pour déterminer longueur du hash
    longueur = int(input("[Longueur du hash en caractères hex (ex: 16, 32, 40, 56, 64, 96, 128) ? ]"))

    if longueur == 32:
        # Cas A
        rep = input("[Trouvé sur une machine Windows / export SAM / format Windows ? (oui/non) ]")
        if rep.lower() == "oui":
            print("[Privilégier NTLM (mode Hashcat -m 1000)]")
            return
        rep = input("[Trouvé dans un dump de base web / fichier users / DB (ex: WordPress, ancien PHP app) ? (oui/non) ]")
        if rep.lower() == "oui":
            print("[Privilégier MD5 (0) ou PHPass si présence de préfixe]")
            return
        rep = input("[Le hash est en majuscules hex (A–F) ? (tout en MAJ) (oui/non) ]")
        if rep.lower() == "oui":
            print("[Augmente la probabilité NTLM]")
        else:
            print("[Augmente la probabilité MD5]")
        rep = input("[Le format original contient ‘user:hash’ ou ‘username:hash’ ? (oui/non) ]")
        if rep.lower() == "oui":
            rep_user = input("[Le nom de l’utilisateur est Windows ? (oui/non) ]")
            if rep_user.lower() == "oui":
                print("[Résultat : NTLM 60%, MD5 30%]")
                print("[Commande Hashcat recommandée : -m 1000]")
            else:
                print("[Résultat : MD5 privilégié]")
                print("[Commande Hashcat recommandée : -m 0]")
        else:
            print("[Résultat : Probabilités non précisées, considérer NTLM ou MD5]")
    
    elif longueur == 40:
        # Cas B
        rep = input("[Provient-il d’un /etc/shadow ou d’un système Unix ? (oui/non) ]")
        if rep.lower() == "oui":
            print("[Moins probable SHA-1 brut ; vérifier préfixe $ (crypt)]")
        rep = input("[Provient-il d’une base de données MySQL (colonne password) ? (oui/non) ]")
        if rep.lower() == "oui":
            print("[MySQL double SHA1 probable (Hashcat -m 300)]")
        else:
            print("[Suggérer SHA-1 (Hashcat -m 100) avec confiance intermédiaire]")
        print("[Proposer Hashcat -m 100 et -m 300 (user choisit)]")
    
    elif longueur == 64:
        # Cas C
        rep = input("[Provient-il d’un système moderne (APIs, JWT, stockage sécurisé) ? (oui/non) ]")
        if rep.lower() == "oui":
            print("[SHA-256 probable]")
        rep = input("[Le hash était encodé en Base64 originellement ? (oui/non) ]")
        if rep.lower() == "oui":
            print("[Considérer décodage Base64 d’abord]")
        print("[SHA-256 recommandé (confiance élevée)]")
    
    elif longueur == 128:
        # Cas D
        rep = input("[Provenance (systèmes UNIX modernes / libs cryptographiques) ? (oui/non) ]")
        if rep.lower() == "oui":
            rep_pref = input("[Présence préfixe style /etc/shadow crypt ($6$) ? (oui/non) ]")
            if rep_pref.lower() == "oui":
                print("[Proposer Whirlpool (-m 6100) ou autre selon préfixe]")
            else:
                print("[SHA-512 probable]")
        else:
            print("[SHA-512 probable sans préfixe]")
        print("[Proposer -m 1700 en priorité]")
    
    elif longueur in [16, 56, 96]:
        # Cas E
        if longueur == 16:
            print("[MySQL323 (ancien) (-m 200)]")
        elif longueur == 56:
            print("[SHA-224, rare]")
        else:
            print("[SHA-384 (-m 10800)]")
    else:
        print("[Longueur non reconnue, impossible d'orienter]")

# Exécution
if __name__ == "__main__":
    arbre_hashcat()
