#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hashly - Outil CLI pour analyser, valider et tester des hashs

Fonctionnalités principales:
- Lecture multi format (.txt, .csv, .json, .xml) en streaming
- Détection automatique de l algo de hash (heuristique simple)
- Validation de format (longueur et type)
- Compteur de hashs lus et testés
- Log des erreurs dans un fichier séparé
- Mode dictionnaire avec wordlist (ex: rockyou.txt)
- Suggestions de commandes Hashcat pour chaque algo détecté
- Export des résultats en CSV ou JSON
- Mode sécurisé pour ne pas afficher les mots de passe en clair
"""

import argparse
import csv
import json
import logging
import os
import re
import sys
import time
import base64
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from collections import defaultdict
from typing import List, Dict, Optional, Iterable

# Tentative d import facultatif de bcrypt
try:
    import bcrypt  # type: ignore
    HAS_BCRYPT = True
except Exception:
    HAS_BCRYPT = False


BANNER = r"""
██╗  ██╗ █████╗ ███████╗██╗  ██╗██╗  ██╗   ██╗
██║  ██║██╔══██╗██╔════╝██║  ██║██║  ╚██╗ ██╔╝
███████║███████║███████╗███████║██║   ╚████╔╝ 
██╔══██║██╔══██║╚════██║██╔══██║██║    ╚██╔╝  
██║  ██║██║  ██║███████║██║  ██║███████╗██║   
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝   

           Hashly - Hash Analysis Toolkit
"""


HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


@dataclass
class AlgorithmCandidate:
    name: str
    algo_id: str
    hashcat_mode: Optional[int]
    confidence: int


@dataclass
class HashEntry:
    hash_str: str
    source_file: str
    line_number: int
    algo_candidates: List[AlgorithmCandidate]
    chosen_algo: Optional[AlgorithmCandidate] = None
    is_valid_format: bool = True
    error: Optional[str] = None
    cracked_password: Optional[str] = None
    crack_time_sec: Optional[float] = None
    status: str = "pending"  # pending, cracked, not_cracked, error


def detect_hash_algorithms(hash_str: str) -> List[AlgorithmCandidate]:
    """
    Détection heuristique simplifiée d algorithmes de hash.
    Retourne une liste de AlgorithmCandidate triés par confiance.
    """
    hash_str = hash_str.strip()
    candidates: List[AlgorithmCandidate] = []

    # Formats spéciaux
    if hash_str.startswith("pbkdf2_sha256$"):
        candidates.append(AlgorithmCandidate(
            name="PBKDF2-HMAC-SHA256 (Django)",
            algo_id="pbkdf2_sha256_django",
            hashcat_mode=10000,
            confidence=100,
        ))
    elif re.match(r'^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$', hash_str):
        candidates.append(AlgorithmCandidate(
            name="bcrypt",
            algo_id="bcrypt",
            hashcat_mode=3200,
            confidence=100,
        ))
    elif HEX_RE.match(hash_str):
        length = len(hash_str)

        if length == 32:
            # MD5 ou NTLM typiquement
            candidates.append(AlgorithmCandidate(
                name="MD5",
                algo_id="md5",
                hashcat_mode=0,
                confidence=80,
            ))
            candidates.append(AlgorithmCandidate(
                name="NTLM (MD4)",
                algo_id="ntlm",
                hashcat_mode=1000,
                confidence=60,
            ))
        elif length == 40:
            candidates.append(AlgorithmCandidate(
                name="SHA-1",
                algo_id="sha1",
                hashcat_mode=100,
                confidence=90,
            ))
        elif length == 64:
            candidates.append(AlgorithmCandidate(
                name="SHA-256",
                algo_id="sha256",
                hashcat_mode=1400,
                confidence=90,
            ))
        elif length == 128:
            candidates.append(AlgorithmCandidate(
                name="SHA-512",
                algo_id="sha512",
                hashcat_mode=1700,
                confidence=90,
            ))
        else:
            candidates.append(AlgorithmCandidate(
                name=f"Hash hex inconnu ({length} chars)",
                algo_id="unknown_hex",
                hashcat_mode=None,
                confidence=10,
            ))
    else:
        candidates.append(AlgorithmCandidate(
            name="Format de hash inconnu",
            algo_id="unknown",
            hashcat_mode=None,
            confidence=0,
        ))

    candidates.sort(key=lambda c: c.confidence, reverse=True)
    return candidates


def looks_like_hash(text: str) -> bool:
    text = text.strip()
    if not text:
        return False
    if text.startswith("pbkdf2_sha256$"):
        return True
    if re.match(r'^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$', text):
        return True
    if HEX_RE.match(text) and len(text) >= 16:
        return True
    return False


def setup_logging(log_file: str) -> None:
    logging.basicConfig(
        filename=log_file,
        filemode="w",
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


def stream_lines_txt(file_path: str) -> Iterable[str]:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            yield line.rstrip("\n")


def stream_hashes_from_txt(file_path: str) -> Iterable[HashEntry]:
    """
    Fichier texte simple.
    On accepte :
    - une ligne = un hash
    - ou cle=hash, cle:hash, hash;cle, etc.
    """
    for idx, line in enumerate(stream_lines_txt(file_path), start=1):
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Essai de split simple
        parts = re.split(r"[;:=,\s]+", line_stripped)
        # On prend le segment qui ressemble le plus a un hash
        hash_candidate = None
        for p in parts:
            if looks_like_hash(p):
                hash_candidate = p
                break

        if not hash_candidate:
            logging.info("Ligne %d dans %s ne contient pas de hash reconnu: %r",
                         idx, file_path, line)
            entry = HashEntry(
                hash_str=line_stripped,
                source_file=file_path,
                line_number=idx,
                algo_candidates=[],
                is_valid_format=False,
                error="Aucun hash reconnu dans la ligne",
                status="error",
            )
            yield entry
            continue

        yield build_hash_entry(hash_candidate, file_path, idx)


def stream_hashes_from_csv(file_path: str) -> Iterable[HashEntry]:
    """
    CSV: on considère que la colonne qui ressemble a un hash est la bonne.
    """
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        for idx, row in enumerate(reader, start=1):
            if not row:
                continue
            hash_candidate = None
            for cell in row:
                if looks_like_hash(cell):
                    hash_candidate = cell.strip()
                    break
            if not hash_candidate:
                logging.info("Ligne %d dans %s ne contient pas de hash reconnu (CSV): %r",
                             idx, file_path, row)
                entry = HashEntry(
                    hash_str=",".join(row),
                    source_file=file_path,
                    line_number=idx,
                    algo_candidates=[],
                    is_valid_format=False,
                    error="Aucun hash reconnu dans la ligne CSV",
                    status="error",
                )
                yield entry
                continue
            yield build_hash_entry(hash_candidate, file_path, idx)


def stream_hashes_from_json(file_path: str) -> Iterable[HashEntry]:
    """
    JSON:
    - soit une liste de strings
    - soit une liste d objets avec champ 'hash'
    - soit un dict avec une cle 'hashes'
    """
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        try:
            data = json.load(f)
        except Exception as e:
            logging.info("Erreur JSON dans %s: %s", file_path, e)
            return

    def handle_hash(value, index: int):
        yield build_hash_entry(str(value), file_path, index)

    index = 0

    if isinstance(data, list):
        for item in data:
            index += 1
            if isinstance(item, dict) and "hash" in item:
                value = item["hash"]
                if looks_like_hash(str(value)):
                    yield from handle_hash(value, index)
                else:
                    logging.info("Element JSON %d dans %s n est pas un hash reconnu", index, file_path)
                    yield HashEntry(
                        hash_str=str(value),
                        source_file=file_path,
                        line_number=index,
                        algo_candidates=[],
                        is_valid_format=False,
                        error="JSON: valeur non reconnue comme hash",
                        status="error",
                    )
            else:
                if looks_like_hash(str(item)):
                    yield from handle_hash(item, index)
                else:
                    logging.info("Element JSON %d dans %s n est pas un hash reconnu (list)", index, file_path)
                    yield HashEntry(
                        hash_str=str(item),
                        source_file=file_path,
                        line_number=index,
                        algo_candidates=[],
                        is_valid_format=False,
                        error="JSON list: valeur non reconnue comme hash",
                        status="error",
                    )

    elif isinstance(data, dict):
        # On parcourt les valeurs du dict a la recherche de champs 'hash'
        for key, value in data.items():
            if key.lower() == "hash" and looks_like_hash(str(value)):
                index += 1
                yield from handle_hash(value, index)
            elif isinstance(value, list):
                for item in value:
                    index += 1
                    if looks_like_hash(str(item)):
                        yield from handle_hash(item, index)
            else:
                continue
    else:
        logging.info("Format JSON inattendu dans %s", file_path)


def stream_hashes_from_xml(file_path: str) -> Iterable[HashEntry]:
    """
    XML: on parcourt tous les elements et on prend le texte qui ressemble a un hash.
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except Exception as e:
        logging.info("Erreur XML dans %s: %s", file_path, e)
        return

    index = 0
    for elem in root.iter():
        if elem.text:
            text = elem.text.strip()
            if looks_like_hash(text):
                index += 1
                yield build_hash_entry(text, file_path, index)


def build_hash_entry(hash_str: str, file_path: str, line_number: int) -> HashEntry:
    candidates = detect_hash_algorithms(hash_str)
    chosen = candidates[0] if candidates else None
    is_valid = True

    if HEX_RE.match(hash_str):
        length = len(hash_str)
        if length < 16:
            is_valid = False

    return HashEntry(
        hash_str=hash_str,
        source_file=file_path,
        line_number=line_number,
        algo_candidates=candidates,
        chosen_algo=chosen,
        is_valid_format=is_valid,
        status="pending" if is_valid else "error",
        error=None if is_valid else "Format invalide",
    )


def detect_file_format(file_path: str) -> str:
    """
    Tente de deviner le format: txt, csv, json ou xml.
    """
    _, ext = os.path.splitext(file_path.lower())
    if ext in [".csv"]:
        return "csv"
    if ext in [".json"]:
        return "json"
    if ext in [".xml"]:
        return "xml"

    # Auto detection sur le contenu
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            first = f.read(2048)
    except Exception:
        return "txt"

    stripped = first.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "json"
    if stripped.startswith("<?xml") or stripped.startswith("<"):
        return "xml"
    if ";" in first or "," in first or ":" in first or "=" in first:
        # probabilite de CSV ou texte cle=valeur
        if "\n" in first and any(c in first for c in [",", ";"]):
            return "csv"
        return "txt"
    return "txt"


def stream_hashes_from_file(file_path: str) -> Iterable[HashEntry]:
    fmt = detect_file_format(file_path)
    if fmt == "csv":
        yield from stream_hashes_from_csv(file_path)
    elif fmt == "json":
        yield from stream_hashes_from_json(file_path)
    elif fmt == "xml":
        yield from stream_hashes_from_xml(file_path)
    else:
        yield from stream_hashes_from_txt(file_path)


def compute_hash(algo_id: str, password: str, full_hash_str: Optional[str] = None) -> Optional[str]:
    """
    Calcule le hash du password pour l algo simple (md5, sha1, sha256, sha512, ntlm).
    Pour pbkdf2 django, on utilise full_hash_str pour recuperer sel et iterations.
    Pour bcrypt, on ne renvoie rien ici, on utilise check_bcrypt.
    """
    import hashlib

    password_bytes = password.encode("utf-8")

    if algo_id == "md5":
        return hashlib.md5(password_bytes).hexdigest()
    if algo_id == "sha1":
        return hashlib.sha1(password_bytes).hexdigest()
    if algo_id == "sha256":
        return hashlib.sha256(password_bytes).hexdigest()
    if algo_id == "sha512":
        return hashlib.sha512(password_bytes).hexdigest()
    if algo_id == "ntlm":
        # NTLM = MD4 de la chaine UTF-16LE
        pw_utf16 = password.encode("utf-16le")
        return hashlib.new("md4", pw_utf16).hexdigest()
    if algo_id == "pbkdf2_sha256_django" and full_hash_str:
        try:
            parts = full_hash_str.split("$")
            # pbkdf2_sha256$iterations$salt$hash
            if len(parts) != 4:
                return None
            _, iters, salt, stored_hash = parts
            iters_int = int(iters)
            dk = hashlib.pbkdf2_hmac(
                "sha256",
                password_bytes,
                salt.encode("utf-8"),
                iters_int,
            )
            calc = base64.b64encode(dk).decode().strip()
            return calc
        except Exception:
            return None

    return None


def check_bcrypt(password: str, full_hash_str: str) -> Optional[bool]:
    if not HAS_BCRYPT:
        return None
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            full_hash_str.encode("utf-8"),
        )
    except Exception:
        return None


def crack_hashes_with_dictionary(
    entries: List[HashEntry],
    wordlist_path: str,
) -> None:
    """
    Mode dictionnaire:
    - regroupe les hashs par algo simple
    - parcourt la wordlist
    """
    if not entries:
        return

    # On regroupe par algo_id
    targets_by_algo: Dict[str, Dict[str, List[HashEntry]]] = defaultdict(lambda: defaultdict(list))

    for e in entries:
        if not e.chosen_algo or not e.is_valid_format:
            continue
        algo_id = e.chosen_algo.algo_id
        targets_by_algo[algo_id][e.hash_str].append(e)

    if not targets_by_algo:
        return

    print("\n[+] Mode dictionnaire active")
    print(f"[+] Wordlist: {wordlist_path}")

    try:
        total_words = sum(1 for _ in open(wordlist_path, "r", encoding="utf-8", errors="ignore"))
    except Exception:
        total_words = None

    for algo_id, targets in targets_by_algo.items():
        if algo_id == "unknown" or algo_id == "unknown_hex":
            continue

        print(f"\n[+] Craquage pour algo: {algo_id} (hashs: {len(targets)})")

        start_algo = time.perf_counter()
        remaining = set(targets.keys())

        # Bcrypt est traite a part car plus lent
        is_bcrypt = (algo_id == "bcrypt")
        if is_bcrypt and not HAS_BCRYPT:
            print("    [!] bcrypt non disponible (bibliotheque bcrypt manquante)")
            continue

        cracked_count = 0

        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as wl:
            for idx, word in enumerate(wl, start=1):
                word = word.rstrip("\n")
                if not word:
                    continue

                if is_bcrypt:
                    # On teste chaque hash restant
                    to_remove = []
                    for h in list(remaining):
                        for entry in targets[h]:
                            ok = check_bcrypt(word, entry.hash_str)
                            if ok:
                                entry.cracked_password = word
                                entry.status = "cracked"
                                entry.crack_time_sec = time.perf_counter() - start_algo
                                cracked_count += 1
                                to_remove.append(h)
                                print(f"    [+] BCRYPT crack: {h} -> {word}")
                                break
                    for h in to_remove:
                        remaining.discard(h)
                    if not remaining:
                        break
                else:
                    # Algo simple
                    for h in list(remaining):
                        any_entry = targets[h][0]
                        calculated = compute_hash(algo_id, word, full_hash_str=any_entry.hash_str)
                        if calculated is None:
                            continue
                        if algo_id == "pbkdf2_sha256_django":
                            # Dans ce cas, le hash stocke deja la version base64, on compare seulement la partie finale
                            parts = any_entry.hash_str.split("$")
                            if len(parts) == 4:
                                stored_hash_part = parts[3]
                            else:
                                continue
                            if calculated == stored_hash_part:
                                for entry in targets[h]:
                                    entry.cracked_password = word
                                    entry.status = "cracked"
                                    entry.crack_time_sec = time.perf_counter() - start_algo
                                    cracked_count += 1
                                remaining.discard(h)
                                print(f"    [+] PBKDF2 crack: {h} -> {word}")
                        else:
                            if calculated.lower() == h.lower():
                                for entry in targets[h]:
                                    entry.cracked_password = word
                                    entry.status = "cracked"
                                    entry.crack_time_sec = time.perf_counter() - start_algo
                                    cracked_count += 1
                                remaining.discard(h)
                                print(f"    [+] Crack: {h} -> {word}")

                if not remaining:
                    break

                if total_words and idx % 100000 == 0:
                    print(f"    ... {idx}/{total_words} mots testes pour {algo_id}")

        duration = time.perf_counter() - start_algo
        print(f"    [=] Terminé pour {algo_id}: {cracked_count} hashs craqués en {duration:.2f}s")


def export_results(entries: List[HashEntry], export_path: str, export_format: str, secure: bool) -> None:
    os.makedirs(os.path.dirname(export_path) or ".", exist_ok=True)

    if secure:
        def mask(p: Optional[str]) -> Optional[str]:
            if p is None:
                return None
            return "*" * len(p) if p else None
    else:
        def mask(p: Optional[str]) -> Optional[str]:
            return p

    rows = []
    for e in entries:
        algo_name = e.chosen_algo.name if e.chosen_algo else "inconnu"
        hashcat_mode = e.chosen_algo.hashcat_mode if e.chosen_algo else None
        rows.append({
            "hash": e.hash_str,
            "file": e.source_file,
            "line": e.line_number,
            "algo": algo_name,
            "hashcat_mode": hashcat_mode,
            "cracked": e.status == "cracked",
            "password": mask(e.cracked_password),
            "crack_time_sec": e.crack_time_sec,
            "valid_format": e.is_valid_format,
            "error": e.error,
        })

    if export_format == "json":
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2, ensure_ascii=False)
    else:
        with open(export_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f, delimiter=";")
            writer.writerow([
                "hash", "file", "line", "algo", "hashcat_mode",
                "cracked", "password", "crack_time_sec",
                "valid_format", "error",
            ])
            for r in rows:
                writer.writerow([
                    r["hash"],
                    r["file"],
                    r["line"],
                    r["algo"],
                    r["hashcat_mode"],
                    r["cracked"],
                    r["password"],
                    r["crack_time_sec"],
                    r["valid_format"],
                    r["error"],
                ])

    print(f"\n[+] Resultats exportes vers: {export_path} ({export_format})")


def print_summary(entries: List[HashEntry]) -> None:
    total = len(entries)
    valid = sum(1 for e in entries if e.is_valid_format)
    errors = sum(1 for e in entries if e.status == "error")
    cracked = sum(1 for e in entries if e.status == "cracked")
    not_cracked = sum(1 for e in entries if e.status == "not_cracked")

    print("\n=========== Synthese ===========")
    print(f"Total hashs lus:     {total}")
    print(f"Hashs valides:       {valid}")
    print(f"Hashs craques:       {cracked}")
    print(f"Hashs non craques:   {not_cracked}")
    print(f"Erreurs de format:   {errors}")

    by_algo = defaultdict(int)
    for e in entries:
        name = e.chosen_algo.name if e.chosen_algo else "inconnu"
        by_algo[name] += 1

    print("\nRepartition par algo detecte:")
    for algo_name, count in sorted(by_algo.items(), key=lambda kv: kv[1], reverse=True):
        print(f"  - {algo_name}: {count}")


def suggest_hashcat_commands(entries: List[HashEntry], original_files: List[str], wordlist_path: Optional[str]) -> None:
    print("\n=========== Suggestions Hashcat ===========")
    algos_seen = {}
    for e in entries:
        if not e.chosen_algo or e.chosen_algo.hashcat_mode is None:
            continue
        mode = e.chosen_algo.hashcat_mode
        algos_seen[e.chosen_algo.algo_id] = (e.chosen_algo.name, mode)

    if not algos_seen:
        print("Aucun algo avec mode Hashcat detecte.")
        return

    input_files = " ".join(set(original_files)) if original_files else "hashes.txt"
    wl = wordlist_path or "rockyou.txt"

    for algo_id, (name, mode) in algos_seen.items():
        print(f"\n[+] {name} (algo_id={algo_id}, mode={mode})")
        print(f"    - Attaque dictionnaire:")
        print(f"      hashcat -m {mode} -a 0 -o results_{algo_id}.txt {input_files} {wl}")
        print(f"    - Attaque brute force (exemple):")
        print(f"      hashcat -m {mode} -a 3 {input_files} ?a?a?a?a")


def main():
    parser = argparse.ArgumentParser(
        description="Hashly - Analyse et craquage de hashs",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-f", "--file",
        dest="files",
        nargs="+",
        required=False,
        help="Fichier(s) de hashs a analyser",
    )
    parser.add_argument(
        "--wordlist",
        "--rockyou",
        dest="wordlist",
        help="Fichier de wordlist (ex: rockyou.txt) pour le mode dictionnaire",
    )
    parser.add_argument(
        "--export",
        dest="export_path",
        help="Fichier de sortie pour les resultats (CSV ou JSON)",
    )
    parser.add_argument(
        "--export-format",
        dest="export_format",
        choices=["csv", "json"],
        default="csv",
        help="Format d export des resultats",
    )
    parser.add_argument(
        "--log",
        dest="log_file",
        default="hashly_errors.log",
        help="Fichier de log pour les erreurs de format",
    )
    parser.add_argument(
        "--secure",
        dest="secure",
        action="store_true",
        help="Mode securise (ne pas afficher les mots de passe en clair)",
    )

    args = parser.parse_args()

    # Mode interactif si aucun fichier n'est fourni
    if not args.files:
        print("\n[+] Aucun fichier fourni.")
        print("[+] Mode interactif : entrez un hash à analyser.")
        user_hash = input("Hash : ").strip()
        if not user_hash:
            print("[!] Aucun hash entré. Arrêt.")
            sys.exit(1)

        # On crée un fichier temporaire virtuel en mémoire
        temp_path = "interactive_input.txt"
        with open(temp_path, "w", encoding="utf-8") as temp_f:
            temp_f.write(user_hash + "\n")

        args.files = [temp_path]
        print(f"[+] Hash enregistré temporairement dans {temp_path}")

    print(BANNER)
    setup_logging(args.log_file)
    print(f"[+] Fichiers en entree: {', '.join(args.files)}")
    if args.wordlist:
        print(f"[+] Wordlist: {args.wordlist}")
    print(f"[+] Fichier de log erreurs: {args.log_file}")

    all_entries: List[HashEntry] = []
    t0 = time.perf_counter()

    # Lecture en streaming fichier par fichier
    for path in args.files:
        if not os.path.isfile(path):
            print(f"[!] Fichier introuvable: {path}")
            continue
        print(f"\n[+] Lecture de {path} ...")
        for entry in stream_hashes_from_file(path):
            all_entries.append(entry)

    # Marquer les hashs valides mais non craques (si on ne fait pas de dictionnaire)
    for e in all_entries:
        if e.status == "pending":
            e.status = "not_cracked"

    # Mode dictionnaire si wordlist
    if args.wordlist:
        crack_hashes_with_dictionary(all_entries, args.wordlist)

    # Stats simple
    t1 = time.perf_counter()
    print_summary(all_entries)
    print(f"\n[+] Temps total d execution: {t1 - t0:.2f}s")

    # Export
    if args.export_path:
        export_results(all_entries, args.export_path, args.export_format, args.secure)

    # Affichage de quelques lignes pour la demo
    print("\n=========== Apercu resultats ===========")
    max_show = 10
    shown = 0
    for e in all_entries:
        if shown >= max_show:
            break
        algo_name = e.chosen_algo.name if e.chosen_algo else "inconnu"
        pwd_display = "***" if args.secure and e.cracked_password else e.cracked_password
        print(f"- {e.hash_str} | {algo_name} | status={e.status} | pwd={pwd_display}")
        shown += 1

    # Suggestions Hashcat
    suggest_hashcat_commands(all_entries, args.files, args.wordlist)

    print("\n[+] Terminé. Bonne chasse aux hashs !")


if __name__ == "__main__":
    main()