def detect_hash(hash_value):
    hash_value = hash_value.strip()
    length = len(hash_value)
    upper = hash_value.isupper()
    resultats = {}

    print(f"\nAnalyse du hash ({length} caractères)...")

    #32 caractères
    if length == 32:
        print("→ Type A : 32 caractères (128 bits)")
        rep = input("Trouvé sur un système Windows (SAM / NTLM) ? (o/n) : ").lower()
        if rep == "o":
            resultats["NTLM (-m 1000)"] = 80
        else:
            rep = input("Trouvé dans une base web (WordPress, PHP, etc.) ? (o/n) : ").lower()
            if rep == "o":
                resultats["MD5 (-m 0)"] = 80
            else:
                resultats["MD5 (-m 0)"] = 50
                resultats["NTLM (-m 1000)"] = 50

        if upper:
            resultats["NTLM (-m 1000)"] = resultats.get("NTLM (-m 1000)", 50) + 10
        else:
            resultats["MD5 (-m 0)"] = resultats.get("MD5 (-m 0)", 50) + 10

    # 40 caractères
    elif length == 40:
        print("→ Type B : 40 caractères (160 bits)")
        rep = input("Hash MySQL ? (o/n) : ").lower()
        if rep == "o":
            resultats["MySQL double SHA1 (-m 300)"] = 80
        else:
            resultats["SHA-1 (-m 100)"] = 70
            resultats["MySQL double SHA1 (-m 300)"] = 30

    #64 caractères
    elif length == 64:
        print("→ Type C : 64 caractères (256 bits)")
        resultats["SHA-256 (-m 1400)"] = 90

    # 128 caractères 
    elif length == 128:
        print("→ Type D : 128 caractères (512 bits)")
        resultats["SHA-512 (-m 1700)"] = 90

    #Autres tailles spécifiques 
    elif length == 16:
        print("→ Type E : 16 caractères (MySQL323)")
        resultats["MySQL323 (-m 200)"] = 90
    elif length == 56:
        print("→ Type E : 56 caractères (SHA-224)")
        resultats["SHA-224"] = 80
    elif length == 96:
        print("→ Type E : 96 caractères (SHA-384)")
        resultats["SHA-384 (-m 10800)"] = 90
    else:
        print("Longueur non reconnue.")
        return

    #Résultats finaux
    print("\nRésultats estimés :")
    for algo, score in sorted(resultats.items(), key=lambda x: x[1], reverse=True):
        print(f" - {algo} : {score}% de probabilité")

    print("\nCommandes Hashcat suggérées :")
    for algo in resultats.keys():
        if "(" in algo:
            mode = algo.split("(-m ")[1].split(")")[0]
            print(f"   hashcat -m {mode} -a 0 hash.txt wordlist.txt  # {algo}")
          
#Exécution
if __name__ == "__main__":
    print("=== Détecteur de type de hash ===")
    h = input("Entrez le hash à analyser : ").strip()
    detect_hash(h)
    input("\nAppuyez sur Entrée pour quitter...")
