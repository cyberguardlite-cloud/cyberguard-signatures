import requests
from pathlib import Path

# Feed ufficiale MalwareBazaar (SHA256 recenti)
FEED_URL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"

OUT_FILE = Path("data/malware_signatures.txt")

def main():
    print("Scarico firme da MalwareBazaar...")

    response = requests.get(FEED_URL, timeout=60)
    response.raise_for_status()

    hashes = set()

    for raw_line in response.text.splitlines():
        line = raw_line.strip()

        # Salta righe vuote e commenti
        if not line or line.startswith("#"):
            continue

        # In caso ci siano separatori strani
        if "|" in line:
            line = line.split("|", 1)[0].strip()

        # Controllo SHA256 valida
        if len(line) == 64 and all(c in "0123456789abcdefABCDEF" for c in line):
            hashes.add(line.lower())

    hashes = sorted(hashes)

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text("\n".join(hashes) + "\n", encoding="utf-8")

    print(f"Salvate {len(hashes)} firme reali.")

if __name__ == "__main__":
    main()
